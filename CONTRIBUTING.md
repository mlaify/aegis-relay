# Contributing to aegis-relay

## Scope

`aegis-relay` is a reference zero-trust store-and-forward relay.

Protocol references:

- `../aegis-spec/docs/protocol-index.md`
- `../aegis-spec/rfcs/RFC-0004-relay-api.md`
- `../aegis-spec/docs/implementation-conformance-v0.1.md`

Local E2E setup:

- `../aegit-cli/DEV-SETUP.md`

## Development Workflow

```sh
cargo fmt
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

## CI Expectations

This repo runs Rust CI for `fmt`, `clippy`, and tests.

## Protocol Change Policy

- Relay API/behavior changes MUST update `RFC-0004` and conformance docs.
- Relay MUST remain passive/untrusted for plaintext and trust decisions.
- Protocol field changes belong in core/spec updates, not relay-local redefinition.

## Current v0.1 Status

Relay is reference-grade infrastructure.

- no authentication/authorization yet
- no replay database yet
- not a production bridge
