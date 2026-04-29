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

## Behavior

- `POST /v1/envelopes` accepts `StoreEnvelopeRequest` JSON from `aegis-api-types` and persists the embedded `Envelope`.
- `POST /v1/envelopes` rejects structurally invalid envelopes with structured relay errors.
- `GET /v1/envelopes/:recipient_id` returns `FetchEnvelopeResponse` JSON from `aegis-api-types`.
- `GET /v1/envelopes/:recipient_id` skips expired envelopes (`expires_at`) and opportunistically removes expired files in file-backed storage.
- `aegit relay fetch --out <dir>` can materialize that response into individual envelope files for local opening with `aegit msg open`.

## Current v0.1.0-alpha Status

This relay is a `v0.1.0-alpha` reference store-and-forward implementation.

- no authentication/authorization yet
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
