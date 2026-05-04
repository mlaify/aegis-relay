# Changelog

All notable changes to this repository are documented here.

## [Unreleased]

### v0.3.0-alpha — phase 1 (relay-side prekey enforcement)

- New `consumed_prekeys` SQLite table with `PRIMARY KEY (recipient_id, key_id)` records every consumed one-time prekey
- New `Store::store_with_prekey_consumption` method performs the envelope insert and per-`key_id` consumption inserts in a single transaction; conflict on any `key_id` rolls back the entire write
- `POST /v1/envelopes` now uses the new path; rejects with `409 prekey_already_used` (offending `key_id` in the message) when any supplied prekey id was already consumed for the recipient
- `validate_envelope` rejects duplicate or empty `key_id` entries within a single `used_prekey_ids` array as `400 invalid_envelope`
- New audit operation `consume_prekey` (outcome `ok` or `conflict`) emitted per consumed key
- `FileStore::store_with_prekey_consumption` is a non-enforcing dev-only fallback; production deployments use `SqliteStore`

### v0.3.0-alpha — phase 2 (prekey publish + atomic claim)

- New `one_time_prekeys` SQLite table with `PRIMARY KEY (identity_id, key_id)` and a `(identity_id, claimed)` index
- New `StoreOutcome::UnknownPrekey { key_id }` variant; `store_with_prekey_consumption` now verifies each `key_id` was published by the recipient before consuming — rejected as `400 unknown_prekey` (consumption transaction rolled back, envelope not stored)
- New trait methods `Store::store_one_time_prekeys` (idempotent `INSERT OR IGNORE`) and `Store::claim_one_time_prekey` (atomic select + `UPDATE … WHERE claimed = 0` in one transaction)
- New `prekey_routes.rs`:
  - `POST /v1/identities/:identity_id/prekeys` (auth-scoped `IdentityWrite`, signature verified against the identity's published Ed25519 + Dilithium3 signing keys; returns `PublishPrekeysResponse { inserted, skipped }`)
  - `GET /v1/identities/:identity_id/prekey` (returns `ClaimedPrekeyResponse { identity_id, key_id, algorithm, public_key_b64 }`; `404 prekey_pool_empty` when exhausted)
- New audit operations `publish_prekeys` (with `inserted=N skipped=M` detail), `claim_prekey` (outcome `ok` / `exhausted`), `consume_prekey` outcome `unknown`
- `FileStore` impls of the new methods are non-enforcing dev-only fallbacks
- 12 new tests added; `48 → 54` tests across the crate

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
