local typedefs = require "kong.db.schema.typedefs"

-- ai-defense-bedrock-signer
--
-- SigV4-signs the proxied request for AWS Bedrock so Kong can forward it through
-- the AI Defense gateway (which relays it to Bedrock unchanged). Credentials come
-- from an assumed IAM role via IRSA (web identity) with a local file fallback - no
-- static keys. This is the plugin form of the inline pre-function signer; running
-- as a real plugin means it needs no KONG_UNTRUSTED_LUA and is config-driven.
return {
  name = "ai-defense-bedrock-signer",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          {
            -- AWS region used for the SigV4 credential scope and the default
            -- signed host (bedrock-runtime.<region>.amazonaws.com).
            region = {
              type = "string",
              default = "us-west-2",
            },
          },
          {
            aws_service = {
              type = "string",
              default = "bedrock",
            },
          },
          {
            -- Host placed in the SigV4 canonical request. Leave empty to derive
            -- bedrock-runtime.<region>.amazonaws.com. Set explicitly when the
            -- upstream (AI Defense gateway) host differs from the signed host.
            signed_host = {
              type = "string",
            },
          },
          {
            -- Where credentials come from:
            --   irsa - assume role via web identity (lua-resty-aws)
            --   file - read creds from files under cred_dir (local/dev)
            --   auto - irsa when role_arn + token file are present, else file
            credential_source = {
              type = "string",
              default = "auto",
              one_of = { "auto", "irsa", "file" },
            },
          },
          {
            -- IAM role to assume for IRSA (e.g. the Kong gateway IRSA role).
            role_arn = {
              type = "string",
            },
          },
          {
            web_identity_token_file = {
              type = "string",
              default = "/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
            },
          },
          {
            role_session_name = {
              type = "string",
              default = "kong-bedrock-signer",
            },
          },
          {
            -- Directory holding the file-based credential fallback.
            -- Expected files: aws-access-key-id, aws-secret-access-key,
            -- aws-session-token (optional), aws-region (optional).
            cred_dir = {
              type = "string",
              default = "/etc/kong/aws",
            },
          },
          {
            -- The Bedrock canonical path is taken from this anchor in the request
            -- path (so /model/<id>/<op> is signed regardless of any route prefix
            -- or strip_path setting).
            model_path_anchor = {
              type = "string",
              default = "/model/",
            },
          },
          {
            -- Upper bound (bytes) for reading the request body into memory before
            -- hashing; larger bodies are stream-hashed from the spooled temp file.
            -- 0 disables the in-memory cap.
            max_body_bytes = {
              type = "integer",
              default = 10485760,
              between = { 0, 104857600 },
            },
          },
        },
        entity_checks = {
          -- IRSA cannot assume a role without an ARN; require it when the source
          -- is explicitly irsa.
          {
            conditional = {
              if_field = "credential_source",
              if_match = { eq = "irsa" },
              then_field = "role_arn",
              then_match = { required = true },
            },
          },
        },
      },
    },
  },
}
