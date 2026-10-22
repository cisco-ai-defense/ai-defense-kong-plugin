-- Copyright 2026 Cisco Systems, Inc. and its affiliates
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- SPDX-License-Identifier: Apache-2.0

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

local function read_request_body_file(max_allowed_file_size)
  local ok, body_file = pcall(ngx.req.get_body_file)
  if not ok then
    return nil, "failed to locate cached request body: " .. tostring(body_file)
  end
  if not body_file then
    return nil, "request body was not available in memory or a temporary file"
  end

  local file, err = io.open(body_file, "rb")
  if not file then
    return nil, "failed to open cached request body: " .. tostring(err)
  end

  local size = file:seek("end")
  if not size then
    file:close()
    return nil, "failed to determine cached request body size"
  end
  if max_allowed_file_size > 0 and size > max_allowed_file_size then
    file:close()
    return nil, ("request body file too big: %d > %d"):format(size, max_allowed_file_size)
  end

  local position, seek_err = file:seek("set")
  if not position then
    file:close()
    return nil, "failed to rewind cached request body: " .. tostring(seek_err)
  end

  local body, read_err = file:read("*a")
  file:close()
  if not body then
    return nil, "failed to read cached request body: " .. tostring(read_err)
  end

  return body
end

local function get_request_body(conf)
  -- Kong normally reads the request body only from Nginx's in-memory client
  -- body buffer. Larger bodies spill to a temporary file, so pass the plugin's
  -- configured limit to let the PDK read that file as well. A limit of 0 is
  -- unlimited; the schema uses a finite default to bound Lua memory use.
  local max_allowed_file_size = conf.max_body_bytes or 0
  local ok, body, err = pcall(kong.request.get_raw_body, max_allowed_file_size)
  if not ok then
    return nil, body
  end

  -- Kong added native file-backed reads in 3.9.2. On older supported versions,
  -- get_raw_body() returns this buffer error; read Nginx's cached body file
  -- directly, enforcing the same configured size limit before allocating it.
  if not body and err
      and tostring(err):match("request body did not fit into client body buffer") then
    return read_request_body_file(max_allowed_file_size)
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

-- Append the text of an Anthropic tool_result block. Its content is either a
-- string or an array of { type = "text", text = ... } parts.
local function append_tool_result(parts, item)
  local inner = item.content
  if type(inner) == "string" and inner ~= "" then
    table.insert(parts, inner)
  elseif type(inner) == "table" then
    for _, sub in ipairs(inner) do
      if type(sub) == "table" and type(sub.text) == "string" and sub.text ~= "" then
        table.insert(parts, sub.text)
      end
    end
  end
end

-- Normalize a message "content" into a plain string. Handles:
--   * OpenAI string content
--   * Bedrock Converse / OpenAI / Anthropic multipart arrays: [{ text = "..." }, ...]
--   * Anthropic tool_result parts, whose text is nested one level down. This is
--     where tool output lands, file contents included, so it must be inspected.
-- Returns nil when no textual content can be extracted.
local function normalize_content(content)
  if type(content) == "string" then
    return content
  end

  if type(content) == "table" then
    local parts = {}
    for _, item in ipairs(content) do
      if type(item) == "table" and type(item.text) == "string" and item.text ~= "" then
        table.insert(parts, item.text)
      elseif type(item) == "table" and item.type == "tool_result" then
        append_tool_result(parts, item)
      end
    end

    if #parts > 0 then
      return table.concat(parts, "\n")
    end

    local ok, encoded = pcall(cjson.encode, content)
    if ok then
      return encoded
    end
  end

  return nil
end

-- A UTF-8 continuation byte (10xxxxxx) never starts a character, so a cut
-- placed on one would split a character and send AI Defense invalid UTF-8.
local function is_continuation(text, pos)
  local b = text:byte(pos)
  return b ~= nil and b >= 0x80 and b < 0xC0
end

-- Keep the start and end of text within max_bytes. Both ends are kept because
-- an injection can sit at either: a pasted document's first line, or a
-- request appended after a long tool output.
local TRUNCATION_MARKER = "\n[... truncated for inspection ...]\n"

local function clip(text, max_bytes)
  if type(text) ~= "string" or not max_bytes or max_bytes <= 0 or #text <= max_bytes then
    return text
  end

  local keep = max_bytes - #TRUNCATION_MARKER
  if keep < 2 then
    keep = max_bytes
  end

  local head_end = math.floor(keep / 2)
  while head_end > 0 and is_continuation(text, head_end + 1) do
    head_end = head_end - 1
  end

  local tail_start = #text - (keep - head_end) + 1
  while tail_start <= #text and is_continuation(text, tail_start) do
    tail_start = tail_start + 1
  end

  return text:sub(1, head_end) .. TRUNCATION_MARKER .. text:sub(tail_start)
end

-- Structured request content for AI Defense. Returns a plain string for string
-- content, or a typed parts array [{type="text",text=...}] for a multipart
-- message, so each text block stays a discrete content part instead of being
-- flattened into one string (a later injection is then not diluted by an
-- earlier benign part, e.g. Claude Code's system-reminder). The set of text
-- inspected is identical to normalize_content (message text + tool_result
-- text), clipped per part. Falls back to normalize_content's behaviour (encoded
-- content) when there is no discrete text, so coverage is unchanged.
local function structured_content(content, max_bytes)
  if type(content) == "string" then
    if content == "" then
      return nil
    end
    return clip(content, max_bytes)
  end

  if type(content) ~= "table" then
    return nil
  end

  -- Collect the inspected text blocks in order (message text + tool_result
  -- text) - the same set normalize_content would gather.
  local texts = {}
  for _, item in ipairs(content) do
    if type(item) == "table" then
      if type(item.text) == "string" and item.text ~= "" then
        texts[#texts + 1] = item.text
      elseif item.type == "tool_result" then
        local tr = {}
        append_tool_result(tr, item)
        for _, txt in ipairs(tr) do
          if txt ~= "" then
            texts[#texts + 1] = txt
          end
        end
      end
    end
  end

  if #texts == 0 then
    -- No discrete text (e.g. a tool_use-only message): preserve
    -- normalize_content's fallback so inspection coverage does not change.
    local normalized = normalize_content(content)
    if type(normalized) == "string" and normalized ~= "" then
      return clip(normalized, max_bytes)
    end
    return nil
  end

  -- The byte budget is per MESSAGE, shared across all its parts - NOT per part.
  -- Applying the limit to each block independently would let N blocks produce
  -- up to N * max_bytes (e.g. two parallel tool_result values ~ 40 KB under a
  -- 20 KB limit), defeating the limit the Anthropic route sets to avoid
  -- oversized inspect/chat calls (which, with fail_closed:false, would forward
  -- uninspected). Account for the "\n" joins used when the parts are combined.
  local total = 0
  for i, t in ipairs(texts) do
    total = total + #t
    if i > 1 then
      total = total + 1
    end
  end

  if max_bytes and max_bytes > 0 and total > max_bytes then
    -- Over the shared budget: truncate the COMBINED message head+tail (so an
    -- injection at either end survives) and send it as one structured text
    -- part. Discreteness is dropped only when the message would otherwise blow
    -- the inspect limit.
    return { { type = "text", text = clip(table.concat(texts, "\n"), max_bytes) } }
  end

  -- Within budget: keep each block as a discrete part so a later injection is
  -- not diluted by an earlier benign part.
  local parts = {}
  for _, t in ipairs(texts) do
    parts[#parts + 1] = { type = "text", text = t }
  end
  return parts
end

-- Tool calls go to AI Defense as OpenAI-style tool_calls, not as text. The
-- difference is not cosmetic: the same "rm -rf /" command is flagged as Tool
-- Exploitation in tool_calls and allowed when it appears as plain assistant
-- text. String input values are clipped individually so the arguments stay
-- valid JSON.
local function tool_call(id, name, input, max_bytes)
  local args
  if type(input) == "table" then
    local clipped = {}
    for k, v in pairs(input) do
      clipped[k] = clip(v, max_bytes)
    end
    args = cjson.encode(clipped) or "{}"
  else
    args = clip(tostring(input or ""), max_bytes)
  end

  return {
    id = id or "call",
    type = "function",
    ["function"] = { name = name or "tool", arguments = args },
  }
end

-- The assistant message AI Defense should see for an Anthropic reply: text
-- blocks as content, tool_use blocks as tool_calls. Thinking blocks are left
-- out; they are not output the user or a tool acts on.
local function anthropic_assistant_message(content, max_bytes)
  local texts, calls = {}, {}
  for _, block in ipairs(content) do
    if type(block) == "table" then
      if block.type == "text" and type(block.text) == "string" and block.text ~= "" then
        table.insert(texts, block.text)
      elseif block.type == "tool_use" then
        table.insert(calls, tool_call(block.id, block.name, block.input, max_bytes))
      end
    end
  end

  if #texts == 0 and #calls == 0 then
    return nil
  end

  local message = { role = "assistant", content = clip(table.concat(texts, "\n"), max_bytes) }
  if #calls > 0 then
    message.tool_calls = calls
  end
  return message
end

-- Reassemble a streamed Anthropic reply (text/event-stream) into the same
-- content blocks a non-streaming reply carries. Blocks arrive one at a time,
-- keyed by index: text as text_delta fragments, tool input as partial JSON
-- that is only parseable once the block is complete.
local function anthropic_sse_content(raw_body)
  if type(raw_body) ~= "string" or not raw_body:find("message_start", 1, true) then
    return nil
  end

  local blocks, order = {}, {}
  for line in raw_body:gmatch("[^\r\n]+") do
    local data = line:match("^data:%s*(.+)$")
    local event = data and cjson.decode(data)
    if type(event) == "table" and event.index ~= nil then
      local idx = event.index
      if event.type == "content_block_start" and type(event.content_block) == "table" then
        local cb = event.content_block
        blocks[idx] = { type = cb.type, id = cb.id, name = cb.name, text = { cb.text or "" }, json = {} }
        table.insert(order, idx)
      elseif event.type == "content_block_delta" and blocks[idx] and type(event.delta) == "table" then
        local delta = event.delta
        if delta.type == "text_delta" and type(delta.text) == "string" then
          table.insert(blocks[idx].text, delta.text)
        elseif delta.type == "input_json_delta" and type(delta.partial_json) == "string" then
          table.insert(blocks[idx].json, delta.partial_json)
        end
      end
    end
  end

  local content = {}
  for _, idx in ipairs(order) do
    local b = blocks[idx]
    if b.type == "text" then
      table.insert(content, { type = "text", text = table.concat(b.text) })
    elseif b.type == "tool_use" then
      local raw_input = table.concat(b.json)
      local input = raw_input ~= "" and cjson.decode(raw_input) or {}
      table.insert(content, { type = "tool_use", id = b.id, name = b.name, input = input or raw_input })
    end
  end
  return content
end

-- Index of the first message in the latest turn: everything after the last
-- assistant message. If the conversation ends on an assistant message (a
-- prefill), that message alone is the turn.
local function latest_turn_start(messages)
  for i = #messages, 1, -1 do
    local m = messages[i]
    if type(m) == "table" and m.role == "assistant" then
      return i < #messages and i + 1 or i
    end
  end
  return 1
end

local function chat_messages_body(raw_body, default_role, opts)
  opts = opts or {}
  local max_bytes = opts.max_message_bytes or 0
  local decoded = cjson.decode(raw_body or "")
  local messages = {}

  -- Streamed Anthropic reply: not JSON, so it is recognised before decoding
  -- matters. Without this the whole event stream would be inspected as one
  -- blob of JSON fragments, with the text split across token-sized deltas.
  if decoded == nil then
    local content = anthropic_sse_content(raw_body)
    local message = content and anthropic_assistant_message(content, max_bytes)
    if message then
      return cjson.encode({ messages = { message } })
    end
  end

  -- Request shape (OpenAI chat completions, Bedrock Converse and the Anthropic
  -- Messages API all use a top-level messages[] array; content may be a string
  -- or a parts array).
  if type(decoded) == "table" and type(decoded.messages) == "table" then
    local first = 1
    if opts.scope == "latest_turn" then
      first = latest_turn_start(decoded.messages)
    end

    for i = first, #decoded.messages do
      local message = decoded.messages[i]
      if type(message) == "table" then
        -- Preserve each text block as a discrete content part (vs flattening to
        -- one string), so an injection in a later part is not diluted by an
        -- earlier benign part. Same inspected text set as before, clipped per
        -- part; plain-string content and the no-text fallback are unchanged.
        local content = structured_content(message.content, max_bytes)
        if content ~= nil then
          table.insert(messages, {
            role = message.role or default_role or "user",
            content = content,
          })
        end
      end
    end

    if #messages > 0 then
      -- System messages go first, other order preserved. AI Defense returns
      -- is_safe=true for a conversation that ENDS on a system message, even
      -- when the user message before it is a plain prompt injection, so a
      -- client could otherwise evade inspection by appending one. Claude Code
      -- does exactly that on every request, with its environment context.
      local ordered = {}
      for _, m in ipairs(messages) do
        if m.role == "system" then table.insert(ordered, m) end
      end
      for _, m in ipairs(messages) do
        if m.role ~= "system" then table.insert(ordered, m) end
      end
      return cjson.encode({ messages = ordered })
    end
  end

  -- Anthropic Messages response shape: top-level content[] of text and
  -- tool_use blocks.
  if type(decoded) == "table" and decoded.type == "message" and type(decoded.content) == "table" then
    local message = anthropic_assistant_message(decoded.content, max_bytes)
    if message then
      return cjson.encode({ messages = { message } })
    end
  end

  -- OpenAI response shape: choices[].message.content
  if type(decoded) == "table" and type(decoded.choices) == "table" then
    for _, choice in ipairs(decoded.choices) do
      local message = type(choice) == "table" and choice.message or nil
      local content = type(message) == "table" and normalize_content(message.content) or nil
      if type(content) == "string" and content ~= "" then
        table.insert(messages, {
          role = (type(message) == "table" and message.role) or default_role or "assistant",
          content = clip(content, max_bytes),
        })
      end
    end
  end

  -- Bedrock Converse response shape: output.message.content[].text
  if #messages == 0
      and type(decoded) == "table"
      and type(decoded.output) == "table"
      and type(decoded.output.message) == "table" then
    local message = decoded.output.message
    local content = normalize_content(message.content)
    if type(content) == "string" and content ~= "" then
      table.insert(messages, {
        role = message.role or default_role or "assistant",
        content = clip(content, max_bytes),
      })
    end
  end

  if #messages == 0 then
    table.insert(messages, {
      role = default_role or "assistant",
      content = clip(raw_body or "", max_bytes),
    })
  end

  return cjson.encode({ messages = messages })
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
    return chat_messages_body(raw_body, "user", {
      scope = conf.chat_messages_scope,
      max_message_bytes = conf.max_message_bytes,
    })
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
    return chat_messages_body(raw_body, "assistant", {
      max_message_bytes = conf.max_message_bytes,
    })
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

-- Map an HTTP status to an Anthropic Messages API error `type`. Used only when
-- client_error_format = "anthropic". Falls back to invalid_request_error so an
-- unmapped status still yields a schema-valid error object.
local ANTHROPIC_ERROR_TYPE = {
  [400] = "invalid_request_error",
  [401] = "authentication_error",
  [403] = "permission_error",
  [404] = "not_found_error",
  [413] = "request_too_large",
  [429] = "rate_limit_error",
  [500] = "api_error",
  [502] = "api_error",
  [529] = "overloaded_error",
}

-- Render the client-facing error body in the shape the caller's SDK expects.
-- "generic" (default) preserves the original envelope exactly, so existing
-- consumers (Bedrock, MCP, custom) are unaffected. "anthropic"/"openai" emit a
-- schema-valid error object so strict clients (e.g. Claude Code on the native
-- Anthropic API) can parse the block/fail response instead of treating it as a
-- malformed reply. Only the body shape changes; status and headers are set by
-- the callers and are unaffected.
local function client_error_payload(conf, status, code, message, decision, phase, txn, event_id, categories)
  local fmt = conf.client_error_format or "generic"

  if fmt == "anthropic" then
    local detail = message
    local cats = categories_header(categories)
    if cats then
      detail = detail .. " [" .. cats .. "]"
    end
    if event_id and event_id ~= "" then
      detail = detail .. " (event_id=" .. event_id .. ")"
    end
    return {
      type = "error",
      error = {
        type = ANTHROPIC_ERROR_TYPE[status] or "invalid_request_error",
        message = detail,
      },
    }
  end

  if fmt == "openai" then
    return {
      error = {
        message = message,
        type = "invalid_request_error",
        code = code,
      },
    }
  end

  -- Default: unchanged generic envelope.
  return error_body(code, message, decision, phase, txn, event_id)
end

local function block_request(conf, categories, event_id)
  local txn = conf.propagate_request_id and request_id() or nil
  return kong.response.exit(conf.block_status,
    client_error_payload(conf, conf.block_status, "AI_DEFENSE_REQUEST_BLOCKED",
      "Request blocked by Cisco AI Defense Policy.", "block", "request", txn, event_id, categories),
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
    local public_message = "Cisco AI Defense request inspection unavailable."
    if code == "AI_DEFENSE_PAYLOAD_TOO_LARGE" then
      public_message = "Request body exceeds the configured inspection size limit."
    end
    return kong.response.exit(status,
      client_error_payload(conf, status, code or "AI_DEFENSE_REQUEST_UNAVAILABLE",
        public_message, "error", "request", txn, nil, nil),
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
  local body = cjson.encode(client_error_payload(conf, conf.block_status, code, message,
      decision, "response", txn, event_id, categories))
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
    local public_message = "Cisco AI Defense response inspection unavailable."
    if code == "AI_DEFENSE_PAYLOAD_TOO_LARGE" then
      public_message = "Response body exceeds the configured inspection size limit."
    end
    set_blocked_response(conf, code or "AI_DEFENSE_RESPONSE_UNAVAILABLE",
      public_message, "error", nil)
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
    request_body, body_err = get_request_body(conf)
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
      -- Kong reports a file-backed body over max_allowed_file_size with this
      -- specific error. Classify it like an oversized in-memory body instead
      -- of reporting a generic body-read failure.
      if (conf.max_body_bytes or 0) > 0
          and tostring(err):match("^request body file too big:") then
        return fail_request_or_continue(conf, 413,
          "request body exceeds max_body_bytes (" .. conf.max_body_bytes .. ")",
          "AI_DEFENSE_PAYLOAD_TOO_LARGE")
      end

      return fail_request_or_continue(conf, 502, "request body could not be read: " .. tostring(err),
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
    -- The buffered body is inspected as-is, and nothing here decompresses it.
    -- Clients such as Claude Code ask for gzip, and a compressed reply would
    -- reach AI Defense as binary, find no violation, and be allowed: a silent
    -- pass rather than an error. So ask the upstream for an uncompressed one.
    kong.service.request.set_header("accept-encoding", "identity")
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
