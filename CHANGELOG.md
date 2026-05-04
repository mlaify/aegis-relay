# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

- Ongoing `v0.2.0-alpha` stabilization.

## [v0.2.0-alpha] - 2026-05-03

### Storage

- SQLite WAL persistence via `tokio-rusqlite` (`storage.rs`); replaces file-backed storage from v0.1
- Indexed `identity_aliases` table for O(1) alias resolution; alias index maintained transactionally in `store_identity`

### Identity endpoints

- `PUT /v1/identities/:id` to publish self-certifying identity documents
- `GET /v1/identities/:id` to resolve by canonical id
- `GET /v1/aliases/:alias` to resolve by alias

### Wire validation

- HybridPq envelope wire fields validated on ingest (rejects malformed PQ envelopes at the edge)

### Auth, audit, retention

- Multi-token auth (`AEGIS_RELAY_AUTH_TOKENS`) with per-scope enforcement (`PushEnvelope`, `IdentityWrite`, `LifecycleChange`)
- Structured JSONL audit sink (`AEGIS_RELAY_AUDIT_LOG_PATH`) emitting events from all write paths
- Retention controls: `AEGIS_RELAY_MAX_MESSAGE_AGE_DAYS`, `AEGIS_RELAY_PURGE_ACKED_ON_CLEANUP`

### Observability

- `GET /v1/status` returns `RelayStatusResponse` (envelope/identity counts, auth config)
- `RelayCleanupResponse.old_removed` reports age-based purges

## [v0.1.0-alpha] - 2026-04-29

- Initial public alpha baseline for the Aegis multi-repo project.
- Scope is explicitly draft/prototype and non-production.
- Demo/local-development crypto workflows only; production PQ is not implemented.
