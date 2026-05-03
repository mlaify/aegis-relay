# aegis-relay

Reference relay server for Aegis.

## Protocol References

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/rfcs/RFC-0004-relay-api.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`
- `../aegis-docs/docs/security-model.md` (human-readable security summary)

## Local Dev Setup

- `../aegit-cli/DEV-SETUP.md`

## Endpoints

- `GET /healthz`
- `POST /v1/envelopes`
- `GET /v1/envelopes/:recipient_id`
- `POST /v1/envelopes/:recipient_id/:envelope_id/ack`
- `DELETE /v1/envelopes/:recipient_id/:envelope_id`
- `POST /v1/cleanup`
- `GET /v1/status`
- `PUT /v1/identities/:identity_id`
- `GET /v1/identities/:identity_id`
- `GET /v1/aliases/:alias`

## Behavior

- `POST /v1/envelopes` accepts `StoreEnvelopeRequest` JSON from `aegis-api-types` and persists the embedded `Envelope`.
- `POST /v1/envelopes` rejects structurally invalid envelopes with structured relay errors.
- `GET /v1/envelopes/:recipient_id` returns `FetchEnvelopeResponse` JSON from `aegis-api-types`.
- `PUT /v1/identities/:identity_id` stores a self-signed identity document after signature validation.
- `GET /v1/identities/:identity_id` fetches identity documents by cryptographic identity id.
- `GET /v1/aliases/:alias` resolves alias hints to identity documents.
- `GET /v1/status` returns aggregate relay counters and auth mode metadata for operators.
- `GET /v1/envelopes/:recipient_id` skips expired envelopes (`expires_at`) and opportunistically removes expired files in file-backed storage.
- lifecycle-changing endpoints (`ack`, `delete`, `cleanup`) support optional local-dev token gating via `AEGIS_RELAY_CAPABILITY_TOKEN`.
- `aegit relay fetch --out <dir>` can materialize that response into individual envelope files for local opening with `aegit msg open`.

## Authorization (Reference)

When token auth is configured, selected write/lifecycle operations require a token header.

Supported headers:

- `Authorization: Bearer <token>`
- `X-Aegis-Relay-Token: <token>`

Environment controls:

- `AEGIS_RELAY_AUTH_TOKENS=token1,token2` (preferred)
- `AEGIS_RELAY_CAPABILITY_TOKEN=token` (legacy fallback)
- `AEGIS_RELAY_REQUIRE_TOKEN_FOR_PUSH=true|false` (default `false`)
- `AEGIS_RELAY_REQUIRE_TOKEN_FOR_IDENTITY_PUT=true|false` (default `true`)

## Retention and Audit Controls

- `AEGIS_RELAY_PURGE_ACKED_ON_CLEANUP=true|false` (default `true`)
- `AEGIS_RELAY_MAX_MESSAGE_AGE_DAYS=<positive integer>` (optional)
- `AEGIS_RELAY_AUDIT_LOG_PATH=/path/to/audit.log` (optional JSONL sink)

## Current v0.1.0-alpha Status

This relay is a `v0.1.0-alpha` reference store-and-forward implementation.

- token auth is reference-only and not a full production identity/authz system
- no replay database yet
- not a production-grade bridge

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

## CI Expectations

GitHub Actions runs `fmt`, `clippy`, and tests for this repo.

## Protocol Change Policy

- Relay API/behavior changes MUST update `RFC-0004` and conformance docs.
- Relay trust boundaries MUST remain zero-trust/untrusted for plaintext.

## Contributing

See `CONTRIBUTING.md`.
