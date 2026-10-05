local cjson = require "cjson.safe"
local http = require "resty.http"

local AiDefenseGuard = {
  VERSION = "0.7.0",
  PRIORITY = 1000,
}

-- Per-profile defaults for payload transformation modes. An explicit
-- request_payload_mode / response_payload_mode in the plugin config always
-- wins; these are only the fallback when the operator did not set one.
local PROFILE_PAYLOAD_DEFAULTS = {
  custom = {
    request_payload_mode = "raw_body",
    response_payload_mode = "inspection_envelope",
  },
  mcp = {
    request_payload_mode = "raw_body",
    response_payload_mode = "mcp_jsonrpc",
  },
  model = {
    request_payload_mode = "chat_messages",
    response_payload_mode = "chat_messages",
  },
}

local function resolve_payload_mode(conf, kind)
  local explicit = conf[kind .. "_payload_mode"]
  if explicit and explicit ~= "" then
    return explicit
  end

  local defaults = PROFILE_PAYLOAD_DEFAULTS[conf.profile] or PROFILE_PAYLOAD_DEFAULTS.custom
  return defaults[kind .. "_payload_mode"]
end

local function sanitize_header_value(value)
  if value == nil then
    return nil
  end

  value = tostring(value):gsub("[\r\n]", " ")
  if #value > 256 then
    return value:sub(1, 253) .. "..."
  end

  return value
end

local function route_name()
  local ok, route = pcall(kong.router.get_route)
  return ok and route and route.name or ""
end

local function service_name()
  local ok, service = pcall(kong.router.get_service)
  return ok and service and service.name or ""
end

-- Correlation id so an AI Defense verdict can be traced back to a Kong request.
-- Prefers Kong's request id (also surfaced as the Kong-Request-ID header),
-- falling back to the nginx request id.
local function request_id()
  local cached = kong.ctx.plugin.tr_id
  if cached and cached ~= "" then
    return cached
  end

  local id
  local ok, value = pcall(function()
    return kong.request.get_id()
  end)
  if ok and value and value ~= "" then
    id = value
  else
    id = ngx.var.request_id or "unknown"
  end

  kong.ctx.plugin.tr_id = id
  return id
end

local function profile_value(conf, model_value, mcp_value, custom_value)
  if conf.profile == "model" then
    return model_value
  end

  if conf.profile == "mcp" then
    return mcp_value
  end

  return custom_value
end

local function get_request_body()
  local ok, body, err = pcall(kong.request.get_raw_body)
  if not ok then
    return nil, body
  end

  return body or "", err
end

local function get_response_body()
  local ok, body = pcall(kong.service.response.get_raw_body)
  if not ok then
    return nil, body
  end

  return body or "", nil
end

local function defense_api_key(conf)
  local ctx_key = kong.ctx.plugin.defense_api_key
  if ctx_key and ctx_key ~= "" then
    return ctx_key
  end

  if conf.defense_api_key and conf.defense_api_key ~= "" then
    return conf.defense_api_key
  end

  if conf.defense_api_key_source_header and conf.defense_api_key_source_header ~= "" then
    return kong.request.get_header(conf.defense_api_key_source_header)
  end

  return nil
end

-- The verdict is driven solely by the AI Defense `action` field:
--   "Block" -> blocked, "Allow" -> allowed.
-- The field may appear at the top level or nested under `result`.
-- Returns "allow", "block", or nil when no recognizable action is present.
local function action_from_body(body)
  if type(body) ~= "table" then
    return nil
  end

  if type(body.result) == "table" then
    local nested = action_from_body(body.result)
    if nested ~= nil then
      return nested
    end
  end

  local action = body.action
  if type(action) ~= "string" then
    return nil
  end

  action = action:lower()
  if action == "allow" then
    return "allow"
  end

  if action == "block" then
    return "block"
  end

  return nil
end

local function reason_from_body(body, fallback)
  if type(body) ~= "table" then
    return fallback
  end

  if type(body.result) == "table" then
    local nested = reason_from_body(body.result, nil)
    if nested ~= nil then
      return nested
    end
  end

  return body.reason
      or body.message
      or body.category
      or body.error
      or body.action
      or fallback
end

-- AI Defense's event id (top level for chat, nested under `result` for MCP).
-- Captured even on allow so it isn't lost when policies run in monitor mode.
local function event_id_from_body(body)
  if type(body) ~= "table" then
    return nil
  end
  -- Only accept a non-empty string. JSON null decodes to a truthy cjson sentinel
  -- and non-scalar values are not header-safe, so ignore them and fall through
  -- to result.event_id rather than emitting a bad header / aborting the request.
  if type(body.event_id) == "string" and body.event_id ~= "" then
    return body.event_id
  end
  if type(body.result) == "table"
      and type(body.result.event_id) == "string" and body.result.event_id ~= "" then
    return body.result.event_id
  end
  return nil
end

-- Best-effort extraction of the triggering ruleset/category names from an AI
-- Defense verdict. The exact response shape can vary, so several common layouts
-- are checked. Returns a de-duplicated list (possibly empty). Used to populate
-- the x-ai-defense-categories header / logs; never the client body.
local function collect_violation_categories(body, acc, seen)
  acc = acc or {}
  seen = seen or {}

  if type(body) ~= "table" then
    return acc
  end

  -- Pattern A: ruleset_types = [{ name, response = { status } }]
  if type(body.ruleset_types) == "table" then
    for _, rs in ipairs(body.ruleset_types) do
      if type(rs) == "table" and type(rs.name) == "string" then
        local status = type(rs.response) == "table" and rs.response.status
        if status and tostring(status):lower() ~= "safe" and not seen[rs.name] then
          seen[rs.name] = true
          table.insert(acc, rs.name)
        end
      end
    end
  end

  -- Pattern B: classifications / categories = ["PII", ...] or [{ name }]
  for _, key in ipairs({ "classifications", "categories" }) do
    if type(body[key]) == "table" then
      for _, c in ipairs(body[key]) do
        local name
        if type(c) == "string" then
          name = c
        elseif type(c) == "table" then
          name = c.name or c.category or c.ruleset
        end
        if name and not seen[name] then
          seen[name] = true
          table.insert(acc, name)
        end
      end
    end
  end

  -- Pattern C: rules = [{ name/rule_name/ruleset, decision }] (block decisions only)
  if type(body.rules) == "table" then
    for _, r in ipairs(body.rules) do
      if type(r) == "table" then
        local name = r.name or r.rule_name or r.ruleset
        local decision = r.decision and tostring(r.decision):lower()
        if name and (decision == "block" or decision == "unsafe") and not seen[name] then
          seen[name] = true
          table.insert(acc, name)
        end
      end
    end
  end

  -- Recurse into a nested result wrapper.
  if type(body.result) == "table" then
    collect_violation_categories(body.result, acc, seen)
  end

  return acc
end

-- Shared memory zone used for both metrics counters and the circuit breaker.
-- Falls back to nil (no-op metrics / per-worker breaker) when the operator did
-- not declare the lua_shared_dict, so the plugin never hard-fails on a missing
-- zone.
local function shared_zone(conf)
  local name = conf.shared_dict
  if not name or name == "" then
    return nil
  end
  return ngx.shared[name]
end

-- Metrics are published through Kong's bundled Prometheus plugin: we register
-- our counters/histogram on the exporter's shared Prometheus instance, so they
-- show up on Kong's existing /metrics endpoint (prefixed with kong_).
--
-- Registration is lazy because this plugin's priority (1000) is higher than the
-- prometheus plugin (13), so the exporter may not be initialized yet during our
-- init_worker. We retry on each request until the instance is available, then
-- cache it per worker. All recording is best-effort and never affects traffic.
local prom_metrics
local prom_warn_logged = false

local function ensure_metrics(conf)
  if not conf.metrics then
    return nil
  end

  if prom_metrics then
    return prom_metrics
  end

  local ok, exporter = pcall(require, "kong.plugins.prometheus.exporter")
  if not ok or type(exporter) ~= "table" or not exporter.get_prometheus then
    return nil
  end

  local prometheus = exporter.get_prometheus()
  if not prometheus then
    if not prom_warn_logged then
      kong.log.warn("AI defense: Prometheus exporter not ready; metrics will ",
        "register once the bundled prometheus plugin is enabled and initialized")
      prom_warn_logged = true
    end
    return nil
  end

  local registered, m = pcall(function()
    return {
      decisions = prometheus:counter(
        "ai_defense_decisions_total",
        "AI Defense allow/block decisions",
        { "phase", "decision" }),
      errors = prometheus:counter(
        "ai_defense_errors_total",
        "AI Defense inspection errors (callout, non-2xx, unparseable)",
        { "phase" }),
      fail_mode = prometheus:counter(
        "ai_defense_fail_mode_total",
        "AI Defense fail-open/fail-closed outcomes when inspection is unavailable",
        { "phase", "mode" }),
      circuit = prometheus:counter(
        "ai_defense_circuit_events_total",
        "AI Defense circuit breaker events",
        { "event" }),
      retries = prometheus:counter(
        "ai_defense_callout_retries_total",
        "AI Defense inspection callout retries",
        { "phase" }),
      latency = prometheus:histogram(
        "ai_defense_callout_latency_ms",
        "AI Defense inspection callout latency in milliseconds",
        { "phase" },
        { 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000 }),
    }
  end)

  if not registered or type(m) ~= "table" then
    kong.log.err("AI defense: failed to register Prometheus metrics: ", tostring(m))
    return nil
  end

  prom_metrics = m
  kong.log.info("AI defense Prometheus metrics registered on Kong exporter")
  return prom_metrics
end

local function record_decision(conf, phase, decision)
  local m = ensure_metrics(conf)
  if m and m.decisions then
    m.decisions:inc(1, { phase, decision })
  end
end

local function record_error(conf, phase)
  local m = ensure_metrics(conf)
  if m and m.errors then
    m.errors:inc(1, { phase })
  end
end

local function record_fail_mode(conf, phase, mode)
  local m = ensure_metrics(conf)
  if m and m.fail_mode then
    m.fail_mode:inc(1, { phase, mode })
  end
end

local function record_circuit(conf, event)
  local m = ensure_metrics(conf)
  if m and m.circuit then
    m.circuit:inc(1, { event })
  end
end

local function record_retry(conf, phase)
  local m = ensure_metrics(conf)
  if m and m.retries then
    m.retries:inc(1, { phase })
  end
end

local function record_latency(conf, phase, elapsed_ms)
  local m = ensure_metrics(conf)
  if m and m.latency then
    m.latency:observe(elapsed_ms, { phase })
  end
end

-- Circuit breaker keyed by defense_url. When AI Defense produces repeated
-- failures the breaker "opens" for a cooldown window; while open we skip the
-- callout entirely and let the configured fail_closed/fail_open behavior apply.
-- Uses the shared zone when available (cluster-consistent per node) and falls
-- back to a per-worker table otherwise.
local cb_worker_state = {}

local function cb_key(conf)
  return conf.defense_url or "default"
end

local function circuit_is_open(conf)
  if not conf.circuit_breaker then
    return false
  end

  local key = cb_key(conf)
  local zone = shared_zone(conf)

  if zone then
    local open_until = zone:get("cb:open:" .. key)
    return open_until ~= nil and open_until > ngx.now()
  end

  local st = cb_worker_state[key]
  return st ~= nil and (st.open_until or 0) > ngx.now()
end

local function circuit_record_success(conf)
  if not conf.circuit_breaker then
    return
  end

  local key = cb_key(conf)
  local zone = shared_zone(conf)

  if zone then
    zone:delete("cb:fails:" .. key)
    zone:delete("cb:open:" .. key)
    return
  end

  cb_worker_state[key] = { failures = 0, open_until = 0 }
end

local function circuit_record_failure(conf)
  if not conf.circuit_breaker then
    return
  end

  local key = cb_key(conf)
  local threshold = conf.circuit_breaker_failures or 5
  local cooldown = conf.circuit_breaker_cooldown_seconds or 30
  local zone = shared_zone(conf)
  local failures

  if zone then
    failures = zone:incr("cb:fails:" .. key, 1, 0)
    if failures and failures >= threshold then
      zone:set("cb:open:" .. key, ngx.now() + cooldown, cooldown)
    end
  else
    local st = cb_worker_state[key] or { failures = 0, open_until = 0 }
    st.failures = (st.failures or 0) + 1
    failures = st.failures
    if failures >= threshold then
      st.open_until = ngx.now() + cooldown
    end
    cb_worker_state[key] = st
  end

  if failures and failures >= threshold then
    record_circuit(conf, "opened")
    kong.log.err(
      "AI defense circuit breaker OPEN",
      " url=", conf.defense_url,
      " failures=", failures,
      " cooldown_s=", cooldown
    )
  end
end

local function call_defense(conf, body, phase)
  if body == nil or body == "" then
    body = "{}"
  end

  if circuit_is_open(conf) then
    record_circuit(conf, "short_circuit")
    kong.log.warn("AI defense ", phase, " skipped: circuit breaker open url=", conf.defense_url)
    return nil, "circuit breaker open: AI defense temporarily unavailable"
  end

  local headers = {
    ["content-type"] = "application/json",
    ["x-ai-defense-phase"] = phase,
    ["x-kong-route"] = route_name(),
    ["x-kong-service"] = service_name(),
  }

  if conf.propagate_request_id then
    headers["x-ai-defense-transaction-id"] = request_id()
  end

  for name, value in pairs(conf.defense_headers or {}) do
    headers[name] = value
  end

  local api_key = defense_api_key(conf)
  if api_key and api_key ~= "" then
    headers[conf.defense_api_key_header] = api_key
  end

  kong.log.info(
    "AI defense ", phase, " inspection starting",
    " url=", conf.defense_url,
    " route=", headers["x-kong-route"],
    " service=", headers["x-kong-service"],
    " payload_bytes=", #body
  )

  local attempts = (conf.max_retries or 0) + 1
  local started_at = ngx.now()
  local res, err

  for attempt = 1, attempts do
    local httpc = http.new()
    httpc:set_timeout(conf.timeout)

    res, err = httpc:request_uri(conf.defense_url, {
      method = "POST",
      body = body,
      headers = headers,
      ssl_verify = conf.ssl_verify,
      keepalive_timeout = 60000,
      keepalive_pool = conf.keepalive_pool or 10,
    })

    if res then
      break
    end

    if attempt < attempts then
      record_retry(conf, phase)
      kong.log.warn(
        "AI defense ", phase, " callout attempt ", attempt, "/", attempts,
        " failed, retrying: ", tostring(err)
      )
    end
  end

  local elapsed_ms = math.floor((ngx.now() - started_at) * 1000)
  record_latency(conf, phase, elapsed_ms)

  -- Transport failure (connection refused, timeout, TLS error, ...).
  if not res then
    circuit_record_failure(conf)
    kong.log.err(
      "AI defense ", phase, " inspection call failed",
      " elapsed_ms=", elapsed_ms,
      " error=", tostring(err)
    )
    return nil, "callout error: " .. tostring(err)
  end

  -- A non-2xx from the inspection API (e.g. 401/403 auth failure, 5xx) is an
  -- operational error, NOT a content decision. Surfacing it as a "block" would
  -- mask misconfiguration, so we route it through the fail-open/closed path
  -- and count it toward the circuit breaker.
  if res.status < 200 or res.status >= 300 then
    circuit_record_failure(conf)
    -- Surface the inspection API's response body (truncated/sanitized): for a
    -- 400 this carries the validation error explaining why the payload was
    -- rejected, which is essential for diagnosing misconfiguration.
    kong.log.err(
      "AI defense ", phase, " inspection returned non-2xx",
      " status=", res.status,
      " elapsed_ms=", elapsed_ms,
      " response_body=", sanitize_header_value(res.body)
    )
    return nil, "AI defense returned HTTP " .. tostring(res.status)
  end

  local parsed_body = cjson.decode(res.body or "")
  local action = action_from_body(parsed_body)
  local reason = reason_from_body(parsed_body, "no explicit action from AI defense")
  local categories = collect_violation_categories(parsed_body)
  local event_id = event_id_from_body(parsed_body)

  kong.log.info(
    "AI defense ", phase, " inspection completed",
    " status=", res.status,
    " elapsed_ms=", elapsed_ms,
    " response_bytes=", #(res.body or ""),
    " action=", tostring(action),
    " categories=", (#categories > 0 and table.concat(categories, ",") or "none"),
    " reason=", sanitize_header_value(reason)
  )

  if action == "allow" then
    circuit_record_success(conf)
    return { allowed = true, reason = reason, status = res.status, categories = categories, event_id = event_id }
  end

  if action == "block" then
    circuit_record_success(conf)
    return { allowed = false, reason = reason, status = res.status, categories = categories, event_id = event_id }
  end

  -- 2xx but no usable verdict: the service is reachable but not returning a
  -- contract-compliant response. Treat as a failure for the breaker.
  circuit_record_failure(conf)
  return nil, "AI defense response missing recognizable action field"
end

local function jsonrpc_id(raw_body)
  local decoded = cjson.decode(raw_body or "")

  if type(decoded) == "table" and decoded.id ~= nil then
    return decoded.id
  end

  return 1
end

local function inspection_envelope(raw_body, name, payload_field, extra_arguments)
  local arguments = extra_arguments or {}
  arguments[payload_field] = raw_body or ""

  return cjson.encode({
    jsonrpc = "2.0",
    id = jsonrpc_id(raw_body),
    method = "tools/call",
    params = {
      name = name,
      arguments = arguments,
    },
  })
end

local function encode_json(value)
  local ok, encoded = pcall(cjson.encode, value)
  return ok and encoded or nil
end

local ALLOWED_IMAGE_MEDIA_TYPES = {
  ["image/png"] = true,
  ["image/jpeg"] = true,
  ["image/gif"] = true,
  ["image/webp"] = true,
}

local function is_inline_image_url(value)
  if type(value) ~= "string" then
    return false
  end
  for media_type in pairs(ALLOWED_IMAGE_MEDIA_TYPES) do
    if value:match("^data:" .. media_type .. ";base64,") then
      return true
    end
  end
  return false
end

local function content_parts(content)
  if type(content) == "string" then
    return content
  end
  if type(content) ~= "table" then
    return nil
  end

  local parts = {}
  for _, item in ipairs(content) do
    if type(item) == "string" then
      if item ~= "" then
        table.insert(parts, { type = "text", text = item })
      end
    elseif type(item) == "table" then
      if type(item.text) == "string" and item.text ~= "" then
        table.insert(parts, { type = "text", text = item.text })
      elseif item.type == "text" and type(item.text) == "string" and item.text ~= "" then
        table.insert(parts, { type = "text", text = item.text })
      elseif item.type == "image_url" and type(item.image_url) == "table"
          and is_inline_image_url(item.image_url.url) then
        table.insert(parts, { type = "image_url", image_url = { url = item.image_url.url } })
      elseif item.type == "image" and type(item.source) == "table"
          and item.source.type == "base64"
          and type(item.source.data) == "string"
          and ALLOWED_IMAGE_MEDIA_TYPES[item.source.media_type] then
        table.insert(parts, {
          type = "image_url",
          image_url = { url = "data:" .. item.source.media_type .. ";base64," .. item.source.data },
        })
      end
    end
  end

  if #parts == 0 then
    -- Preserve compatibility with existing provider-specific multipart bodies
    -- that do not use one of the supported text/image shapes.
    return encode_json(content)
  end
  if #parts == 1 and parts[1].type == "text" then
    return parts[1].text
  end
  return parts
end

local function normalized_tool_calls(calls)
  local out = {}
  if type(calls) ~= "table" then
    return out
  end

  for _, call in ipairs(calls) do
    local fn = type(call) == "table" and call["function"] or nil
    if type(call) == "table" and type(fn) == "table"
        and type(fn.name) == "string" and fn.name ~= "" then
      local arguments = fn.arguments
      if type(arguments) ~= "string" then
        arguments = encode_json(arguments or {}) or "{}"
      end
      table.insert(out, {
        id = type(call.id) == "string" and call.id or nil,
        type = "function",
        ["function"] = { name = fn.name, arguments = arguments },
      })
    end
  end
  return out
end

local function append_chat_message(messages, source, default_role)
  if type(source) ~= "table" then
    return
  end

  local role = source.role
  if role == "developer" then
    role = "system"
  end
  if role ~= "system" and role ~= "user" and role ~= "assistant"
      and role ~= "tool" and role ~= "function" then
    role = default_role or "user"
  end
  local content = source.content
  local tool_calls = normalized_tool_calls(source.tool_calls)

  if type(content) == "table" then
    local content_blocks, anthropic_calls = {}, tool_calls
    local function flush_text_and_calls()
      local merged_content
      if #content_blocks == 1 and content_blocks[1].type == "text" then
        merged_content = content_blocks[1].text
      elseif #content_blocks > 0 then
        merged_content = content_blocks
      end
      if merged_content ~= nil or #anthropic_calls > 0 then
        local message = { role = role, content = merged_content or "" }
        if #anthropic_calls > 0 then
          message.tool_calls = anthropic_calls
        end
        table.insert(messages, message)
      end
      content_blocks, anthropic_calls = {}, {}
    end

    for _, item in ipairs(content) do
      if type(item) == "table" and item.type == "tool_result" then
        -- Anthropic returns tool results as blocks in a user message. The
        -- inspection contract represents each result as its own tool message.
        flush_text_and_calls()
        local result_content = content_parts(item.content)
        local tool_call_id = type(item.tool_use_id) == "string" and item.tool_use_id or nil
        if (result_content ~= nil and result_content ~= "") or (tool_call_id and tool_call_id ~= "") then
          table.insert(messages, {
            role = "tool",
            tool_call_id = tool_call_id,
            content = result_content or "",
          })
        end
      elseif type(item) == "table" and item.type == "tool_use" then
        local arguments = encode_json(item.input or {}) or "{}"
        if type(item.name) == "string" and item.name ~= "" then
          table.insert(anthropic_calls, {
            id = type(item.id) == "string" and item.id or nil,
            type = "function",
            ["function"] = { name = item.name, arguments = arguments },
          })
        end
      elseif type(item) == "table" and item.type == "thinking" then
        -- Do not send private chain-of-thought blocks to the inspector.
      elseif type(item) == "table" and item.type == "redacted_thinking" then
        -- Redacted reasoning has no user-visible content to inspect.
      else
        local part = content_parts({ item })
        if type(part) == "string" and part ~= "" then
          table.insert(content_blocks, { type = "text", text = part })
        elseif type(part) == "table" then
          for _, normalized_part in ipairs(part) do
            table.insert(content_blocks, normalized_part)
          end
        end
      end
    end
    flush_text_and_calls()
    return
  end

  local normalized_content = content_parts(content)
  if (normalized_content ~= nil and normalized_content ~= "") or #tool_calls > 0 then
    local message = { role = role, content = normalized_content or "" }
    if type(source.tool_call_id) == "string" then
      message.tool_call_id = source.tool_call_id
    end
    if #tool_calls > 0 then
      message.tool_calls = tool_calls
    end
    table.insert(messages, message)
  end
end

local function anthropic_system_message(messages, system)
  local content = content_parts(system)
  if type(content) == "string" and content ~= "" then
    table.insert(messages, 1, { role = "system", content = content })
  elseif type(content) == "table" then
    local text = {}
    for _, part in ipairs(content) do
      if part.type == "text" and part.text ~= "" then
        table.insert(text, part.text)
      end
    end
    if #text > 0 then
      table.insert(messages, 1, { role = "system", content = table.concat(text, "\n") })
    end
  end
end

local function normalized_tool_definitions(tools)
  local out = {}
  if type(tools) ~= "table" then
    return out
  end

  for _, tool in ipairs(tools) do
    if type(tool) == "table" then
      local fn = tool["function"]
      local parameters = tool.input_schema
      if type(fn) == "table" then
        parameters = fn.parameters
      end
      local name = tool.name or (type(fn) == "table" and fn.name)
      if type(name) == "string" and name ~= "" then
        local description = tool.description or (type(fn) == "table" and fn.description)
        if type(description) ~= "string" then
          description = ""
        end
        table.insert(out, {
          type = "function",
          ["function"] = {
            name = name,
            description = description,
            parameters = type(parameters) == "string" and parameters or encode_json(parameters or {}) or "{}",
          },
        })
      end
    end
  end
  return out
end

local function chat_messages_body(raw_body, default_role)
  local decoded = cjson.decode(raw_body or "")
  local messages, tools = {}, {}
  local recognized_chat_shape = false

  if type(decoded) == "table" then
    if decoded.system ~= nil then
      anthropic_system_message(messages, decoded.system)
    end

    if type(decoded.messages) == "table" then
      recognized_chat_shape = true
      for _, message in ipairs(decoded.messages) do
        append_chat_message(messages, message, default_role or "user")
      end
      tools = normalized_tool_definitions(decoded.tools)
    end

    -- OpenAI response shape: choices[].message.content
    if #messages == 0 and type(decoded.choices) == "table" then
      recognized_chat_shape = true
      for _, choice in ipairs(decoded.choices) do
        local message = type(choice) == "table" and choice.message or nil
        append_chat_message(messages, message, "assistant")
      end
    end

    -- Anthropic Messages API response shape.
    if #messages == 0 and decoded.type == "message" and decoded.role == "assistant" then
      recognized_chat_shape = true
      append_chat_message(messages, decoded, "assistant")
    end

    -- Bedrock Converse response shape: output.message.content[].text
    if #messages == 0 and type(decoded.output) == "table"
        and type(decoded.output.message) == "table" then
      recognized_chat_shape = true
      local message = decoded.output.message
      append_chat_message(messages, message, "assistant")
    end
  end

  if #messages == 0 then
    -- Avoid forwarding an empty provider turn or re-embedding Anthropic
    -- thinking-only JSON as prompt text. ChatInspectRequest requires a message,
    -- so use an explicit empty-analysis marker when the recognized payload had
    -- no supported user-visible content or tool calls.
    local content = recognized_chat_shape and "[No inspectable chat content]" or (raw_body or "")
    table.insert(messages, { role = default_role or "assistant", content = content })
  end

  local inspection_request = { messages = messages }
  if #tools > 0 then
    inspection_request.tools = tools
  end
  return cjson.encode(inspection_request)
end

local function looks_like_json(value)
  if type(value) ~= "string" then
    return false
  end

  value = value:gsub("^%s+", "")
  return value:sub(1, 1) == "{" or value:sub(1, 1) == "["
end

-- The AI Defense MCP inspect endpoint requires `method` and `params` in the
-- body for response inspection, but an MCP JSON-RPC response only carries
-- `id` + `result`/`error`. Merge the originating request's method/params
-- (captured during the access phase) with the response result so the endpoint
-- receives {jsonrpc, id, method, params, result}.
local function merge_mcp_response(resp)
  local ctx = kong.ctx.plugin.mcp_request or {}

  local merged = {
    jsonrpc = "2.0",
    id = (type(resp) == "table" and resp.id) or ctx.id or 1,
  }

  if ctx.method ~= nil then
    merged.method = ctx.method
  end
  if ctx.params ~= nil then
    merged.params = ctx.params
  end

  if type(resp) == "table" then
    if resp.result ~= nil then
      merged.result = resp.result
    end
    if resp.error ~= nil then
      merged.error = resp.error
    end
  end

  return merged
end

local function mcp_jsonrpc_body(raw_body)
  -- Direct JSON-RPC object (a response carries jsonrpc/result/error).
  local decoded = cjson.decode(raw_body or "")
  if type(decoded) == "table"
      and (decoded.jsonrpc ~= nil or decoded.result ~= nil or decoded.error ~= nil) then
    return cjson.encode(merge_mcp_response(decoded))
  end

  -- SSE-wrapped JSON-RPC payload(s).
  local merged_items = {}
  for line in tostring(raw_body or ""):gmatch("([^\r\n]+)") do
    local data = line:match("^data:%s*(.+)$")
    if data and data ~= "[DONE]" and looks_like_json(data) then
      local item = cjson.decode(data)
      if type(item) == "table" then
        table.insert(merged_items, merge_mcp_response(item))
      end
    end
  end

  if #merged_items == 1 then
    return cjson.encode(merged_items[1])
  end

  if #merged_items > 1 then
    return cjson.encode(merged_items)
  end

  -- Nothing decodable: still emit request context so inspection has method/params.
  return cjson.encode(merge_mcp_response(decoded))
end

-- Capture the MCP JSON-RPC request's method/params/id so the response phase
-- can build a contract-compliant merged inspection payload.
local function capture_mcp_request(raw_body)
  local decoded = cjson.decode(raw_body or "")
  if type(decoded) == "table" and decoded.method ~= nil then
    kong.ctx.plugin.mcp_request = {
      method = decoded.method,
      params = decoded.params,
      id = decoded.id,
    }
  end
end

local DEFAULT_MCP_CONTROL_METHODS = {
  "initialize",
  "initialized",
  "ping",
  "notifications/initialized",
  "tools/list",
  "resources/list",
  "prompts/list",
}

-- When the request is an MCP JSON-RPC control/handshake message with no
-- scannable content, return its method name so the caller can bypass the
-- (wasteful) inspection callout. Returns nil otherwise.
local function mcp_control_method(conf, raw_body)
  if not conf.mcp_bypass_control_methods then
    return nil
  end

  local decoded = cjson.decode(raw_body or "")
  if type(decoded) ~= "table" then
    return nil
  end

  -- Only JSON-RPC payloads (single object) are eligible; batches/arrays and
  -- non-RPC bodies are always inspected.
  if decoded.jsonrpc == nil and decoded.method == nil then
    return nil
  end

  local method = decoded.method
  if type(method) ~= "string" then
    return nil
  end

  local control = conf.mcp_control_methods
  if not control or #control == 0 then
    control = DEFAULT_MCP_CONTROL_METHODS
  end

  for _, name in ipairs(control) do
    if name == method then
      return method
    end
  end

  return nil
end

local function request_inspection_body(conf, raw_body)
  local payload_mode = resolve_payload_mode(conf, "request")
  if payload_mode == "chat_messages" then
    return chat_messages_body(raw_body, "user")
  end

  if payload_mode == "raw_body" then
    return raw_body
  end

  local inspection_name = profile_value(conf, "kong_model_request_inspection", conf.request_inspection_name, conf.request_inspection_name)
  local payload_field = profile_value(conf, "request", conf.request_payload_field, conf.request_payload_field)

  return inspection_envelope(raw_body, inspection_name, payload_field, {
    tr_id = conf.propagate_request_id and request_id() or nil,
    path = kong.request.get_path(),
    method = kong.request.get_method(),
  })
end

local function response_inspection_body(conf, raw_body)
  local payload_mode = resolve_payload_mode(conf, "response")
  if payload_mode == "chat_messages" then
    return chat_messages_body(raw_body, "assistant")
  end

  if payload_mode == "mcp_jsonrpc" then
    return mcp_jsonrpc_body(raw_body)
  end

  if payload_mode == "raw_body" then
    return raw_body
  end

  local inspection_name = profile_value(conf, "kong_model_response_inspection", "kong_mcp_response_inspection", conf.response_inspection_name)
  local payload_field = profile_value(conf, "response", "response", conf.response_payload_field)

  return inspection_envelope(raw_body, inspection_name, payload_field, {
    tr_id = conf.propagate_request_id and request_id() or nil,
    upstream_status = kong.response.get_status(),
  })
end

-- Standard client-facing error envelope. Detail (reason/categories) stays in
-- logs and headers; the body is intentionally generic to avoid leaking
-- inspection internals or detected content to the caller.
local function error_body(code, message, decision, phase, txn, event_id)
  return {
    error = {
      code = code,
      message = message,
      decision = decision,
      phase = phase,
      transaction_id = txn,
      event_id = event_id,
    },
  }
end

local function categories_header(categories)
  if type(categories) == "table" and #categories > 0 then
    return table.concat(categories, ",")
  end
  return nil
end

local function block_request(conf, categories, event_id)
  local txn = conf.propagate_request_id and request_id() or nil
  return kong.response.exit(conf.block_status,
    error_body("AI_DEFENSE_REQUEST_BLOCKED", "Request blocked by Cisco AI Defense Policy.",
      "block", "request", txn, event_id),
    {
      ["x-ai-defense-decision"] = "block",
      ["x-ai-defense-phase"] = "request",
      ["x-ai-defense-categories"] = categories_header(categories),
      ["x-ai-defense-transaction-id"] = txn,
      ["x-ai-defense-request-event-id"] = event_id,
    })
end

local function fail_request_or_continue(conf, status, message, code)
  record_error(conf, "request")
  kong.log.err("AI defense request check failed (fail_closed=", tostring(conf.fail_closed), "): ", message)

  if conf.fail_closed then
    record_fail_mode(conf, "request", "closed")
    local txn = conf.propagate_request_id and request_id() or nil
    return kong.response.exit(status,
      error_body(code or "AI_DEFENSE_REQUEST_UNAVAILABLE",
        "Cisco AI Defense request inspection unavailable.", "error", "request", txn),
      {
        ["x-ai-defense-decision"] = "error",
        ["x-ai-defense-phase"] = "request",
        ["x-ai-defense-transaction-id"] = txn,
      })
  end

  record_fail_mode(conf, "request", "open")
  kong.service.request.set_header("x-ai-defense-request-decision", "skipped")
  kong.service.request.set_header("x-ai-defense-request-reason", sanitize_header_value(message))
end

local function set_blocked_response(conf, code, message, decision, categories, event_id)
  local txn = conf.propagate_request_id and request_id() or nil
  local body = cjson.encode(error_body(code, message, decision, "response", txn, event_id))
      or '{"error":{"code":"' .. code .. '","decision":"' .. decision .. '","phase":"response"}}'

  kong.response.set_status(conf.block_status)
  kong.response.set_header("content-type", "application/json")
  kong.response.set_header("x-ai-defense-decision", decision)
  kong.response.set_header("x-ai-defense-phase", "response")
  local cats = categories_header(categories)
  if cats then
    kong.response.set_header("x-ai-defense-categories", cats)
  end
  if event_id and event_id ~= "" then
    kong.response.set_header("x-ai-defense-response-event-id", event_id)
  end
  if txn then
    kong.response.set_header("x-ai-defense-transaction-id", txn)
  end
  kong.response.clear_header("content-length")
  kong.response.clear_header("content-encoding")

  local ok, err = pcall(kong.response.set_raw_body, body)
  if not ok then
    kong.log.err("could not replace blocked response body: ", err)
  end
end

local function fail_response_or_continue(conf, message, code)
  record_error(conf, "response")
  kong.log.err("AI defense response check failed (fail_closed=", tostring(conf.fail_closed), "): ", message)

  if conf.fail_closed then
    record_fail_mode(conf, "response", "closed")
    set_blocked_response(conf, code or "AI_DEFENSE_RESPONSE_UNAVAILABLE",
      "Cisco AI Defense response inspection unavailable.", "error", nil)
    return
  end

  record_fail_mode(conf, "response", "open")
  kong.response.set_header("x-ai-defense-response-decision", "skipped")
  kong.response.set_header("x-ai-defense-response-reason", sanitize_header_value(message))
end

-- Returns true when a configured max_body_bytes limit (>0) is exceeded.
local function body_too_large(conf, body)
  local limit = conf.max_body_bytes or 0
  return limit > 0 and body ~= nil and #body > limit
end

function AiDefenseGuard:access(conf)
  if conf.defense_api_key_source_header and conf.defense_api_key_source_header ~= "" then
    kong.ctx.plugin.defense_api_key = kong.request.get_header(conf.defense_api_key_source_header)
    kong.service.request.clear_header(conf.defense_api_key_source_header)
  end

  if conf.propagate_request_id then
    kong.service.request.set_header("x-ai-defense-transaction-id", request_id())
  end

  -- MCP response inspection needs the request's method/params, so the body must
  -- be read even when request inspection itself is disabled.
  local need_mcp_request_ctx = conf.check_response
      and resolve_payload_mode(conf, "response") == "mcp_jsonrpc"

  -- Read the body once if inspection, MCP-bypass detection, or MCP response
  -- context capture needs it.
  local request_body, body_err
  if conf.check_request or conf.mcp_bypass_control_methods or need_mcp_request_ctx then
    request_body, body_err = get_request_body()
  end

  -- MCP control-message bypass: handshakes (initialize, tools/list, ping, ...)
  -- carry no scannable content, so skip the inspection callout entirely for
  -- both the request and the corresponding response.
  if conf.mcp_bypass_control_methods and not body_err and request_body then
    local method = mcp_control_method(conf, request_body)
    if method then
      kong.ctx.plugin.mcp_bypassed = true
      record_decision(conf, "request", "bypass")
      kong.log.info("AI defense: MCP control message '", method,
        "' bypassed inspection (tr=", request_id(), ")")
      kong.service.request.set_header("x-ai-defense-request-decision", "bypassed")
      return
    end
  end

  -- Remember the MCP request method/params for the response inspection merge.
  if need_mcp_request_ctx and not body_err and request_body then
    capture_mcp_request(request_body)
  end

  if conf.check_request then
    local body, err = request_body, body_err
    if err then
      return fail_request_or_continue(conf, 413, "request body could not be read: " .. tostring(err),
        "AI_DEFENSE_REQUEST_UNAVAILABLE")
    end

    body = body or ""

    if body_too_large(conf, body) then
      return fail_request_or_continue(conf, 413,
        "request body " .. #body .. " bytes exceeds max_body_bytes (" .. conf.max_body_bytes .. ")",
        "AI_DEFENSE_PAYLOAD_TOO_LARGE")
    end

    kong.log.info("AI defense request validation enabled")

    local decision
    local inspection_body = request_inspection_body(conf, body)
    if not inspection_body then
      return fail_request_or_continue(conf, 502, "request inspection body could not be encoded",
        "AI_DEFENSE_REQUEST_UNAVAILABLE")
    end

    decision, err = call_defense(conf, inspection_body, "request")
    if not decision then
      return fail_request_or_continue(conf, 502, err, "AI_DEFENSE_REQUEST_UNAVAILABLE")
    end

    if not decision.allowed then
      record_decision(conf, "request", "block")
      kong.log.warn("request blocked by AI defense: ", decision.reason,
        " categories=", categories_header(decision.categories) or "none")
      return block_request(conf, decision.categories, decision.event_id)
    end

    record_decision(conf, "request", "allow")
    kong.log.info("AI defense request validation allowed reason=", sanitize_header_value(decision.reason))
    kong.service.request.set_header("x-ai-defense-request-decision", "allow")
    kong.service.request.set_header("x-ai-defense-request-reason", sanitize_header_value(decision.reason))
    if decision.event_id and decision.event_id ~= "" then
      kong.response.set_header("x-ai-defense-request-event-id", decision.event_id)
    end
  end

  if conf.check_response then
    kong.service.request.enable_buffering()
  end
end

function AiDefenseGuard:response(conf)
  if not conf.check_response or kong.response.get_source() ~= "service" then
    return
  end

  -- The matching request was an MCP control/handshake message; nothing to scan.
  if kong.ctx.plugin.mcp_bypassed then
    kong.log.info("AI defense: skipping response scan for bypassed MCP control message")
    return
  end

  local upstream_body, err = get_response_body()
  if err then
    return fail_response_or_continue(conf, "response body could not be read: " .. tostring(err),
      "AI_DEFENSE_RESPONSE_UNAVAILABLE")
  end

  if body_too_large(conf, upstream_body) then
    return fail_response_or_continue(conf,
      "response body " .. #upstream_body .. " bytes exceeds max_body_bytes (" .. conf.max_body_bytes .. ")",
      "AI_DEFENSE_PAYLOAD_TOO_LARGE")
  end

  local inspection_body = response_inspection_body(conf, upstream_body)
  if not inspection_body then
    return fail_response_or_continue(conf, "response inspection body could not be encoded",
      "AI_DEFENSE_RESPONSE_UNAVAILABLE")
  end

  kong.log.info(
    "AI defense response validation enabled",
    " upstream_status=", kong.response.get_status(),
    " upstream_body_bytes=", #(upstream_body or ""),
    " inspection_payload_bytes=", #inspection_body
  )

  local decision
  decision, err = call_defense(conf, inspection_body, "response")
  if not decision then
    return fail_response_or_continue(conf, err, "AI_DEFENSE_RESPONSE_UNAVAILABLE")
  end

  if not decision.allowed then
    record_decision(conf, "response", "block")
    kong.log.warn("response blocked by AI defense: ", decision.reason,
      " categories=", categories_header(decision.categories) or "none")
    set_blocked_response(conf, "AI_DEFENSE_RESPONSE_BLOCKED", "Response blocked by Cisco AI Defense Policy.",
      "block", decision.categories, decision.event_id)
    return
  end

  record_decision(conf, "response", "allow")
  kong.log.info("AI defense response validation allowed reason=", sanitize_header_value(decision.reason))
  kong.response.set_header("x-ai-defense-response-decision", "allow")
  kong.response.set_header("x-ai-defense-response-reason", sanitize_header_value(decision.reason))
  if decision.event_id and decision.event_id ~= "" then
    kong.response.set_header("x-ai-defense-response-event-id", decision.event_id)
  end
  if conf.propagate_request_id then
    kong.response.set_header("x-ai-defense-transaction-id", request_id())
  end
end

return AiDefenseGuard
