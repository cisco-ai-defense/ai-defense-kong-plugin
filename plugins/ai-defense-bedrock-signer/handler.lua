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


-- ai-defense-bedrock-signer
--
-- Signs the proxied request with AWS SigV4 for Bedrock, then lets Kong forward it
-- (e.g. to the AI Defense gateway, which relays the signed request to Bedrock
-- unchanged). AI Defense does NOT sign - Kong does, here.
--
-- Credentials: an assumed IAM role via IRSA (web identity, lua-resty-aws), cached
-- and auto-refreshed per worker; falls back to files under cred_dir for local dev.
-- No static keys. Runs as a trusted plugin, so no KONG_UNTRUSTED_LUA is required.
--
-- Low PRIORITY so it runs after auth and any request transformers: it signs the
-- FINAL request, so "what AWS verifies is exactly what the gateway sends".

local openssl_hmac = require "resty.openssl.hmac"
local resty_sha256 = require "resty.sha256"
local to_hex       = require("resty.string").to_hex

local AiDefenseBedrockSigner = {
  VERSION = "0.1.0",
  PRIORITY = 10,
}

-- Per-worker IRSA credential providers, keyed by role ARN. lua-resty-aws caches
-- and refreshes the assumed-role temp creds inside each provider object.
local irsa_providers = {}

local function sha256_hex(s)
  local d = resty_sha256:new()
  d:update(s or "")
  return to_hex(d:final())
end

local function hmac256(key, msg)
  local h = assert(openssl_hmac.new(key, "sha256"))
  return assert(h:final(msg))
end

local function read_file(path)
  local fh = io.open(path, "rb")
  if not fh then
    return nil
  end
  local c = fh:read("*a")
  fh:close()
  if c then
    c = c:gsub("%s+$", "")
  end
  if not c or c == "" then
    return nil
  end
  return c
end

-- Returns access_key, secret_key, session_token (session_token may be nil), or
-- nil + error.
local function resolve_credentials(conf)
  local source = conf.credential_source or "auto"
  local token_file = conf.web_identity_token_file

  local use_irsa
  if source == "irsa" then
    use_irsa = true
  elseif source == "file" then
    use_irsa = false
  else -- auto
    use_irsa = (conf.role_arn ~= nil and conf.role_arn ~= "")
      and (read_file(token_file) ~= nil)
  end

  if use_irsa then
    if not conf.role_arn or conf.role_arn == "" then
      return nil, nil, nil, "role_arn is required for IRSA credential source"
    end

    local provider = irsa_providers[conf.role_arn]
    if not provider then
      local AWS = require("resty.aws")
      local aws = AWS({ region = conf.region })
      provider = aws:TokenFileWebIdentityCredentials({
        token_file   = token_file,
        role_arn     = conf.role_arn,
        session_name = conf.role_session_name,
      })
      irsa_providers[conf.role_arn] = provider
    end

    local ok, access_key, secret_key, session_token = provider:get()
    if not ok then
      -- on failure, access_key carries the error message
      return nil, nil, nil, "IRSA credential error: " .. tostring(access_key)
    end
    return access_key, secret_key, session_token
  end

  -- File-based fallback (local/dev).
  local dir = conf.cred_dir
  local access_key   = read_file(dir .. "/aws-access-key-id")
  local secret_key   = read_file(dir .. "/aws-secret-access-key")
  local session_token = read_file(dir .. "/aws-session-token")
  return access_key, secret_key, session_token
end

-- SHA-256 (hex) of the exact request body. Bodies within max_body_bytes are hashed
-- in memory; larger ones are stream-hashed from the nginx temp file so we never
-- pin the whole body in RAM. Either way nginx forwards the buffered body unchanged.
local function body_payload_hash(conf)
  local raw
  local max = conf.max_body_bytes or 0
  if max > 0 then
    local ok, body = pcall(kong.request.get_raw_body, max)
    if ok then
      raw = body
    end
  else
    raw = kong.request.get_raw_body()
  end

  if raw and raw ~= "" then
    return sha256_hex(raw)
  end

  local path = ngx.req.get_body_file()
  if path then
    local fh = io.open(path, "rb")
    if not fh then
      return nil, "cannot read buffered request body file"
    end
    local d = resty_sha256:new()
    while true do
      local chunk = fh:read(65536)
      if not chunk then
        break
      end
      d:update(chunk)
    end
    fh:close()
    return to_hex(d:final())
  end

  return sha256_hex("")
end

function AiDefenseBedrockSigner:access(conf)
  local region  = conf.region
  local service = conf.aws_service
  local host    = conf.signed_host
  if not host or host == "" then
    host = "bedrock-runtime." .. region .. ".amazonaws.com"
  end

  local access_key, secret_key, session_token, cred_err = resolve_credentials(conf)
  if cred_err then
    kong.log.err("[ai-defense-bedrock-signer] ", cred_err)
    return kong.response.exit(500, { message = "Bedrock signing: credential error" })
  end
  if not access_key or not secret_key then
    return kong.response.exit(500, { message = "Bedrock signing: AWS credentials not available" })
  end

  -- Bedrock-native canonical path (/model/<id>/<op>), independent of any route
  -- prefix: anchor on model_path_anchor and percent-encode ':' in the model id.
  local full = kong.request.get_path() or "/"
  local anchor = conf.model_path_anchor or "/model/"
  local idx = full:find(anchor, 1, true)
  local upstream_path = idx and full:sub(idx) or full
  local canonical_uri = (upstream_path:gsub(":", "%%3A"))

  local payload_hash, body_err = body_payload_hash(conf)
  if not payload_hash then
    kong.log.err("[ai-defense-bedrock-signer] ", body_err)
    return kong.response.exit(500, { message = "Bedrock signing: request body unavailable" })
  end

  local method    = kong.request.get_method()
  local amzdate    = os.date("!%Y%m%dT%H%M%SZ")
  local datestamp  = os.date("!%Y%m%d")

  local canonical_headers, signed_headers
  if session_token then
    canonical_headers = "content-type:application/json\n"
      .. "host:" .. host .. "\n"
      .. "x-amz-date:" .. amzdate .. "\n"
      .. "x-amz-security-token:" .. session_token .. "\n"
    signed_headers = "content-type;host;x-amz-date;x-amz-security-token"
  else
    canonical_headers = "content-type:application/json\n"
      .. "host:" .. host .. "\n"
      .. "x-amz-date:" .. amzdate .. "\n"
    signed_headers = "content-type;host;x-amz-date"
  end

  local canonical_request = method .. "\n"
    .. canonical_uri .. "\n"
    .. "\n"                       -- canonical query string (Bedrock ops have none)
    .. canonical_headers .. "\n"
    .. signed_headers .. "\n"
    .. payload_hash

  local algorithm        = "AWS4-HMAC-SHA256"
  local credential_scope = datestamp .. "/" .. region .. "/" .. service .. "/aws4_request"
  local string_to_sign   = algorithm .. "\n"
    .. amzdate .. "\n"
    .. credential_scope .. "\n"
    .. sha256_hex(canonical_request)

  local k_date    = hmac256("AWS4" .. secret_key, datestamp)
  local k_region  = hmac256(k_date, region)
  local k_service = hmac256(k_region, service)
  local k_signing = hmac256(k_service, "aws4_request")
  local signature = to_hex(hmac256(k_signing, string_to_sign))

  local authorization = algorithm
    .. " Credential=" .. access_key .. "/" .. credential_scope
    .. ", SignedHeaders=" .. signed_headers
    .. ", Signature=" .. signature

  kong.service.request.set_header("Authorization", authorization)
  kong.service.request.set_header("X-Amz-Date", amzdate)
  kong.service.request.set_header("Content-Type", "application/json")
  if session_token then
    kong.service.request.set_header("X-Amz-Security-Token", session_token)
  else
    -- Don't let a caller-supplied token leak into the signed request.
    kong.service.request.clear_header("X-Amz-Security-Token")
  end
end

return AiDefenseBedrockSigner
