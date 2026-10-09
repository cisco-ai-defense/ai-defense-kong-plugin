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

local typedefs = require "kong.db.schema.typedefs"

return {
  name = "ai-defense-intercept",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            profile = {
              type = "string",
              default = "custom",
              one_of = { "custom", "mcp", "model" },
            },
          },
          {
            -- The AI Defense inspection endpoint. Comes from the plugin
            -- config and MUST be HTTPS: inspection traffic carries full
            -- prompts/responses, so plaintext is not permitted.
            defense_url = {
              type = "string",
              required = true,
              match = "^https://",
            },
          },
          {
            defense_api_key = {
              type = "string",
              encrypted = true,
              referenceable = true,
            },
          },
          {
            defense_api_key_header = {
              type = "string",
              default = "X-Cisco-AI-Defense-API-Key",
            },
          },
          {
            defense_api_key_source_header = {
              type = "string",
            },
          },
          {
            defense_headers = {
              type = "map",
              keys = { type = "string" },
              values = { type = "string" },
              default = {},
            },
          },
          {
            timeout = {
              type = "integer",
              default = 10000,
              between = { 100, 60000 },
            },
          },
          {
            fail_closed = {
              type = "boolean",
              default = true,
            },
          },
          {
            block_status = {
              type = "integer",
              default = 400,
              between = { 400, 599 },
            },
          },
          {
            check_request = {
              type = "boolean",
              default = true,
            },
          },
          {
            check_response = {
              type = "boolean",
              default = true,
            },
          },
          {
            request_payload_mode = {
              type = "string",
              one_of = { "raw_body", "inspection_envelope", "chat_messages" },
            },
          },
          {
            response_payload_mode = {
              type = "string",
              one_of = { "raw_body", "inspection_envelope", "chat_messages", "mcp_jsonrpc" },
            },
          },
          {
            request_inspection_name = {
              type = "string",
              default = "kong_request_inspection",
            },
          },
          {
            response_inspection_name = {
              type = "string",
              default = "kong_response_inspection",
            },
          },
          {
            request_payload_field = {
              type = "string",
              default = "request",
            },
          },
          {
            response_payload_field = {
              type = "string",
              default = "response",
            },
          },
          {
            ssl_verify = {
              type = "boolean",
              default = true,
            },
          },
          {
            -- Maximum payload size (bytes) read for inspection and sent to AI
            -- Defense. The finite default bounds per-request Lua memory use.
            -- 0 explicitly disables the plugin limit. When exceeded, the
            -- configured fail_closed behavior applies (block) or the
            -- request/response is allowed through uninspected (fail open).
            max_body_bytes = {
              type = "integer",
              default = 10485760,
              between = { 0, 104857600 },
            },
          },
          {
            -- Number of extra attempts on a transport-level callout failure
            -- (connection/timeout/TLS). HTTP status codes are not retried.
            max_retries = {
              type = "integer",
              default = 1,
              between = { 0, 5 },
            },
          },
          {
            -- Size of the per-worker keepalive connection pool to AI Defense.
            keepalive_pool = {
              type = "integer",
              default = 10,
              between = { 1, 1000 },
            },
          },
          {
            -- When AI Defense keeps failing, stop calling it for a cooldown
            -- window and apply the fail_closed/fail_open behavior directly.
            circuit_breaker = {
              type = "boolean",
              default = true,
            },
          },
          {
            -- Consecutive failures (transport, non-2xx, or unparseable
            -- response) before the breaker opens.
            circuit_breaker_failures = {
              type = "integer",
              default = 5,
              between = { 1, 1000 },
            },
          },
          {
            -- How long the breaker stays open before allowing a trial call.
            circuit_breaker_cooldown_seconds = {
              type = "integer",
              default = 30,
              between = { 1, 3600 },
            },
          },
          {
            -- Publish metrics through Kong's bundled Prometheus plugin
            -- (Kong's /metrics endpoint, prefixed kong_ai_defense_*). Requires
            -- the prometheus plugin to be enabled. No-op when disabled.
            metrics = {
              type = "boolean",
              default = true,
            },
          },
          {
            -- Name of an nginx lua_shared_dict used for cross-worker
            -- circuit-breaker state. Declare it in kong.conf:
            --   nginx_http_lua_shared_dict = ai_defense 16m
            -- If absent, the breaker falls back to per-worker state.
            shared_dict = {
              type = "string",
              default = "ai_defense",
            },
          },
          {
            -- Skip the inspection callout for MCP JSON-RPC control/handshake
            -- messages that carry no scannable content.
            mcp_bypass_control_methods = {
              type = "boolean",
              default = true,
            },
          },
          {
            -- MCP JSON-RPC methods treated as control messages and bypassed.
            mcp_control_methods = {
              type = "array",
              elements = { type = "string" },
              default = {
                "initialize",
                "initialized",
                "ping",
                "notifications/initialized",
                "tools/list",
                "resources/list",
                "prompts/list",
              },
            },
          },
          {
            -- Propagate the Kong request id to AI Defense (as the
            -- x-ai-defense-transaction-id header and a tr_id field in envelope
            -- payloads) and reflect it back to the client for correlation.
            propagate_request_id = {
              type = "boolean",
              default = true,
            },
          },
        },
        entity_checks = {
          -- Inspection cannot authenticate without a key from one of these
          -- sources, so require the operator to configure at least one.
          {
            at_least_one_of = {
              "defense_api_key",
              "defense_api_key_source_header",
            },
          },
        },
      },
    },
  },
}
