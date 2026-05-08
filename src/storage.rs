use std::path::{Path, PathBuf};

use crate::config::RetentionPolicy;
use aegis_proto::{Envelope, IdentityDocument, PrekeyBundle};
use async_trait::async_trait;
use chrono::Utc;
use rusqlite::OptionalExtension;
use tokio_rusqlite::Connection;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleOutcome {
    Deleted,
    Acknowledged,
    NotFound,
}

/// Outcome of `store_with_prekey_consumption`.
///
/// `Stored` indicates the envelope was persisted and any prekey ids in
/// `used_prekey_ids` were recorded as consumed atomically.
///
/// `PrekeyAlreadyUsed` indicates one of the supplied `key_id` values is
/// already on record for the recipient — the envelope was NOT stored and
/// no new consumption was recorded.
///
/// `UnknownPrekey` indicates a `key_id` in `used_prekey_ids` does not match
/// any prekey published by the recipient — the envelope was NOT stored.
/// (v0.3 phase 2: senders MUST claim a prekey before referencing it.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreOutcome {
    Stored,
    PrekeyAlreadyUsed { key_id: String },
    UnknownPrekey { key_id: String },
}

/// One unclaimed one-time prekey, returned by `claim_one_time_prekey`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedPrekey {
    pub identity_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key_b64: String,
}

/// Result of publishing a `PrekeyBundle` — counts new vs. duplicate
/// `(identity_id, key_id)` rows, so the caller can report idempotency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PublishPrekeyReport {
    pub inserted: usize,
    pub skipped: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupReport {
    pub expired_removed: usize,
    pub orphan_ack_removed: usize,
    pub old_removed: usize,
}

/// One row from the admin identity list.
#[derive(Debug, Clone)]
pub struct IdentityListEntry {
    pub identity_id: String,
    pub aliases: Vec<String>,
    pub updated_at: String,
}

/// One row from the served-domains table.
#[derive(Debug, Clone)]
pub struct DomainEntry {
    pub domain: String,
    pub verification_token: String,
    pub verified_at: Option<String>,
    pub added_at: String,
}

/// One row from the provisioned-users roster.
#[derive(Debug, Clone)]
pub struct ProvisionedUserEntry {
    pub alias: String,
    pub identity_id: Option<String>,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Outcome of `provision_user`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    Created,
    AlreadyExists,
    DomainNotServed,
}

/// Outcome of `deprovision_user`. Both fields are surfaced through the
/// admin API + audit log so operators can see what got cleaned up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeprovisionOutcome {
    /// True if a `provisioned_users` row matched and was removed. False
    /// means the alias was never provisioned (HTTP 404 on the admin API).
    pub alias_removed: bool,
    /// Number of envelopes purged from the queue. Zero when the alias was
    /// never bound to an identity, or when no envelopes were addressed to
    /// the bound identity.
    pub envelopes_purged: u64,
}

/// One row from the federation outbound-delivery queue. The queue is the
/// bridge between "this relay stored an envelope" and "the recipient's
/// authoritative relay accepts it" (mlaify/aegis-relay#28).
#[derive(Debug, Clone)]
pub struct OutboundDelivery {
    pub envelope_id: String,
    pub target_url: String,
    pub status: String, // "pending" | "delivered" | "expired"
    pub attempts: u32,
    /// Earliest time at which a `status='pending'` row should be retried.
    /// In the past for "due now", in the future for "backed off". Stored as
    /// RFC-3339; ordering is lexicographic UTC-safe.
    pub next_retry_at: String,
    pub last_error: Option<String>,
    pub last_attempt_at: Option<String>,
    pub created_at: String,
}

/// The relay's own hybrid signing identity, used to sign delivery
/// receipts (#32). Loaded once at boot and kept in `AppState`. Both
/// JSON fields are the same shapes the FFI emits for client identities
/// — round-trip-compatible with `aegis_proto::IdentityDocument` and
/// `aegis_identity::HybridPqPrivateKeyMaterial`.
#[derive(Debug, Clone)]
pub struct RelayIdentity {
    pub identity_id: String,
    /// The signed `IdentityDocument` JSON. Exposed verbatim via
    /// `/.well-known/aegis-config` so peers can discover this relay's
    /// signing keys for receipt verification.
    pub document_json: String,
    /// `HybridPqPrivateKeyMaterial` JSON. Stays inside the relay; never
    /// served. Used to sign receipts.
    pub secrets_json: String,
}

/// Aggregated snapshot of the federation queue, returned by
/// `Storage::federation_metrics`. Used to back `GET /admin/federation/metrics`
/// (mlaify/aegis-relay#31). `recent_*` counts are scoped to the
/// caller-supplied sliding window (default 24h at the route layer).
#[derive(Debug, Clone)]
pub struct FederationMetricsSnapshot {
    pub queue: QueueStats,
    pub targets: Vec<TargetStats>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueueStats {
    /// Rows currently in `status='pending'` regardless of when they were
    /// enqueued. The freshest indicator of real-time backlog.
    pub pending: u64,
    /// Rows that flipped to `delivered` within the window. Counted by
    /// `delivered_at` so retroactive operator queries see consistent data.
    pub delivered_recent: u64,
    /// Rows that exhausted retries within the window.
    pub expired_recent: u64,
    /// Rows superseded by a sibling target's success within the window
    /// (multi-target failover, #30).
    pub superseded_recent: u64,
    /// Age in whole seconds of the oldest still-pending row. `None` when
    /// the queue is empty — operators read this as "everything's clean".
    pub oldest_pending_age_seconds: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetStats {
    pub target_url: String,
    pub pending: u64,
    pub delivered_recent: u64,
    pub expired_recent: u64,
    pub superseded_recent: u64,
    /// 50th percentile of `attempts` across delivered rows in the window.
    /// 1 means most envelopes succeeded on the first try.
    pub p50_attempts: u32,
    /// 95th percentile of `attempts`. Diverging p50 vs p95 is the signal
    /// of "a meaningful slice of traffic is fighting backoff" — the most
    /// useful number for spotting a degraded peer.
    pub p95_attempts: u32,
    /// Most-recent `delivered_at` for this target within the window.
    pub last_success_at: Option<String>,
    /// Most-recent `last_attempt_at` for an `expired` row in the window.
    pub last_failure_at: Option<String>,
}

/// Outcome of `claim_provisioned_alias` — used during identity PUT to enforce
/// that an alias reserved for one identity_id cannot be hijacked by another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimAliasOutcome {
    /// Alias not in roster — allow without binding (open mode).
    NotProvisioned,
    /// Alias bound to this identity_id (either fresh claim or matches existing).
    Bound,
    /// Alias bound to a different identity_id — reject.
    OwnedByOther { identity_id: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayMetrics {
    pub envelopes_total: usize,
    pub envelopes_acknowledged: usize,
    pub envelopes_active: usize,
    pub identities_total: usize,
}

// ---------------------------------------------------------------------------
// Store trait
// ---------------------------------------------------------------------------

#[async_trait]
pub trait Store: Send + Sync {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    /// Store an envelope and atomically record each `key_id` in
    /// `envelope.used_prekey_ids` as consumed for `envelope.recipient_id`.
    ///
    /// If any `key_id` is already on record as consumed for the recipient,
    /// returns `Ok(StoreOutcome::PrekeyAlreadyUsed { key_id })` and persists
    /// neither the envelope nor any partial consumption record.
    ///
    /// When `used_prekey_ids` is empty this is equivalent to `store` and
    /// returns `Ok(StoreOutcome::Stored)`.
    async fn store_with_prekey_consumption(
        &self,
        envelope: &Envelope,
    ) -> Result<StoreOutcome, Box<dyn std::error::Error + Send + Sync>>;
    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>>;
    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>>;
    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>>;
    async fn cleanup(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>>;
    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>>;
    async fn resolve_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>>;
    async fn metrics(&self) -> Result<RelayMetrics, Box<dyn std::error::Error + Send + Sync>>;
    /// Publish all one-time prekeys from `bundle` into the unclaimed pool.
    ///
    /// Idempotent: existing `(identity_id, key_id)` rows are kept as-is
    /// (so re-publishing a partially-consumed bundle does not reset the
    /// `claimed` flag on already-consumed entries).
    async fn store_one_time_prekeys(
        &self,
        bundle: &PrekeyBundle,
    ) -> Result<PublishPrekeyReport, Box<dyn std::error::Error + Send + Sync>>;
    /// Atomically claim one unclaimed one-time prekey for `identity_id` and
    /// mark it consumed. Returns `None` if the unclaimed pool is empty.
    async fn claim_one_time_prekey(
        &self,
        identity_id: &str,
    ) -> Result<Option<ClaimedPrekey>, Box<dyn std::error::Error + Send + Sync>>;
    /// Paginated list of identities ordered by `updated_at DESC`.
    async fn list_identities(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<IdentityListEntry>, Box<dyn std::error::Error + Send + Sync>>;

    // -- Served domains -------------------------------------------------------

    /// Paginated list of claimed domains ordered by `added_at ASC` (oldest
    /// first; matches the original unsorted-feel of pre-paginated callers).
    async fn list_served_domains(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DomainEntry>, Box<dyn std::error::Error + Send + Sync>>;

    /// Total count of claimed domains. Pairs with `list_served_domains` so
    /// the admin API can return total alongside the paginated slice without
    /// forcing every caller to compute it from a full scan.
    async fn count_served_domains(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>;

    /// Add a domain claim with a freshly-generated verification token.
    /// Returns the existing entry if the domain is already claimed (idempotent).
    async fn add_served_domain(
        &self,
        domain: &str,
        verification_token: &str,
    ) -> Result<DomainEntry, Box<dyn std::error::Error + Send + Sync>>;

    async fn get_served_domain(
        &self,
        domain: &str,
    ) -> Result<Option<DomainEntry>, Box<dyn std::error::Error + Send + Sync>>;

    /// Mark a domain as verified. Returns `false` if the domain is not claimed.
    async fn mark_domain_verified(
        &self,
        domain: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    /// Release a domain. Cascades alias purge for all identities claiming
    /// addresses under this domain. Returns the number of aliases removed.
    async fn release_served_domain(
        &self,
        domain: &str,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>>;

    /// True iff at least one verified domain is configured (i.e. relay is in
    /// "managed" mode rather than open-publish).
    async fn has_served_domains(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>;

    // -- Provisioned users ----------------------------------------------------

    async fn list_provisioned_users(
        &self,
        domain_filter: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ProvisionedUserEntry>, Box<dyn std::error::Error + Send + Sync>>;

    /// Reserve an alias for future identity binding.
    /// Returns `DomainNotServed` if the alias domain is not in `served_domains`
    /// or `AlreadyExists` if the alias is already provisioned.
    async fn provision_user(
        &self,
        alias: &str,
    ) -> Result<ProvisionOutcome, Box<dyn std::error::Error + Send + Sync>>;

    /// Remove a provisioned-user reservation, drop the alias index row, AND
    /// purge envelopes addressed to the bound identity. Returns the
    /// `(alias_removed, envelopes_purged)` pair so the admin API can surface
    /// the count in the response and the audit log.
    ///
    /// Why purge envelopes: the Phase 1 spec calls for deprovision to "revoke
    /// alias, purge envelopes" (see RFC-0004 §user-provisioning). Envelopes
    /// are keyed by `recipient_id` (identity_id), not by alias, so we look up
    /// the bound identity_id from `identity_aliases` before deleting the
    /// alias row, then drop every envelope addressed to that identity.
    ///
    /// If the alias has no bound identity (status='provisioned' but never
    /// claimed), `envelopes_purged` is 0 — there's nothing tied to it yet.
    async fn deprovision_user(
        &self,
        alias: &str,
    ) -> Result<DeprovisionOutcome, Box<dyn std::error::Error + Send + Sync>>;

    /// Check whether an alias is provisioned and to whom. Used at identity
    /// PUT time to gate alias binding.
    async fn claim_provisioned_alias(
        &self,
        alias: &str,
        identity_id: &str,
    ) -> Result<ClaimAliasOutcome, Box<dyn std::error::Error + Send + Sync>>;

    // -- Outbound federation queue (#28) --------------------------------------
    //
    // When this relay stores an envelope addressed to a recipient whose
    // IdentityDocument lists a *different* relay's URL in `relay_endpoints`,
    // the federation worker pushes the envelope to that relay over HTTPS.
    // The queue persists across restarts so deliveries survive crashes /
    // remote-relay outages, with exponential backoff up to a configurable
    // attempt cap.

    /// Fetch a single envelope's raw JSON by id, regardless of recipient
    /// or acknowledged state. Used by the federation worker to forward
    /// the exact bytes the sender produced (signature canonicalization
    /// is byte-sensitive — round-tripping through `Envelope` would
    /// preserve semantics but might shuffle field order).
    async fn fetch_envelope_json(
        &self,
        envelope_id: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>>;

    /// Enqueue a delivery row. Idempotent on `(envelope_id, target_url)` —
    /// duplicates are silently ignored so callers don't have to dedupe at
    /// the route layer (e.g. a retried `POST /v1/envelopes` shouldn't double-
    /// enqueue).
    async fn enqueue_outbound_delivery(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Pull the oldest `status='pending'` row whose `next_retry_at <= now`.
    /// Returns `None` when nothing is due — the federation worker uses this
    /// as its sleep signal.
    async fn next_pending_delivery(
        &self,
    ) -> Result<Option<OutboundDelivery>, Box<dyn std::error::Error + Send + Sync>>;

    /// Record a failed attempt. Increments `attempts`, sets `last_error` and
    /// `last_attempt_at`, and pushes `next_retry_at` to whatever the
    /// federation worker computed via its backoff schedule.
    async fn mark_delivery_attempt(
        &self,
        envelope_id: &str,
        target_url: &str,
        error: &str,
        next_retry_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Mark a delivery as `delivered`, drop the local envelope copy,
    /// AND flip every other still-`pending` row for the same envelope
    /// to `superseded` (#30 multi-target failover).
    ///
    /// All three writes happen in a single SQL transaction so we can't
    /// end up with stale "still pending" siblings after the envelope is
    /// known to have landed somewhere, nor with a "delivered" row whose
    /// envelope still sits in the local queue.
    ///
    /// Returns the list of target URLs that got transitioned from
    /// `pending` → `superseded` so the federation worker can audit-log
    /// each one with the same level of detail it produced when they
    /// were initially attempted.
    async fn mark_delivery_delivered(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>>;

    /// Mark a delivery as `expired` (max attempts exhausted). The local
    /// envelope copy is preserved — the operator may still want to retry
    /// manually or a subsequent gateway path may pick it up.
    async fn mark_delivery_expired(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Aggregated metrics over the federation queue, scoped to a sliding
    /// `window_seconds` (typically 86400 for a day). Returns queue-level
    /// totals + per-target rollups including p50/p95 attempt counts.
    /// Drives `GET /admin/federation/metrics` (#31).
    async fn federation_metrics(
        &self,
        window_seconds: i64,
    ) -> Result<FederationMetricsSnapshot, Box<dyn std::error::Error + Send + Sync>>;

    // -- Relay self-identity (#32) --------------------------------------------

    /// Load the relay's own signing identity (slot='primary'), or `None`
    /// if it hasn't been generated yet. Called at startup; if `None`,
    /// the boot path generates a fresh identity and persists it via
    /// [`save_relay_identity`].
    async fn load_relay_identity(
        &self,
    ) -> Result<Option<RelayIdentity>, Box<dyn std::error::Error + Send + Sync>>;

    /// Persist a freshly-generated relay identity. Idempotent on
    /// `slot='primary'` — calling again with a different identity
    /// overwrites the existing one (intentional, but the boot path
    /// only writes when load returned `None`).
    async fn save_relay_identity(
        &self,
        identity: &RelayIdentity,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Persist the signed delivery receipt that came back from a peer
    /// when a federation push succeeded. Used by the federation worker
    /// after a successful delivery; the JSON is exactly the
    /// `DeliveryReceipt` blob the peer returned in its response body.
    /// (#32)
    async fn save_delivery_receipt(
        &self,
        envelope_id: &str,
        target_url: &str,
        receipt_json: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// FileStore
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub struct FileStore {
    base: PathBuf,
}

impl FileStore {
    #[allow(dead_code)]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            base: path.as_ref().to_path_buf(),
        }
    }

    fn envelope_path(&self, recipient_id: &str, envelope_id: &str) -> PathBuf {
        self.base
            .join(safe_name(recipient_id))
            .join(format!("{envelope_id}.json"))
    }

    fn ack_path(&self, recipient_id: &str, envelope_id: &str) -> PathBuf {
        self.base
            .join(safe_name(recipient_id))
            .join(format!("{envelope_id}.ack"))
    }
}

#[async_trait]
impl Store for FileStore {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join(safe_name(&envelope.recipient_id.0));
        tokio::fs::create_dir_all(&dir).await?;
        let file = dir.join(format!("{}.json", envelope.envelope_id.0));
        let data = serde_json::to_vec_pretty(envelope)?;
        tokio::fs::write(file, data).await?;
        Ok(())
    }

    async fn store_with_prekey_consumption(
        &self,
        envelope: &Envelope,
    ) -> Result<StoreOutcome, Box<dyn std::error::Error + Send + Sync>> {
        // FileStore is a dev/testing fallback and does not implement prekey
        // consumption tracking. Production deployments use SqliteStore.
        self.store(envelope).await?;
        Ok(StoreOutcome::Stored)
    }

    async fn store_one_time_prekeys(
        &self,
        bundle: &PrekeyBundle,
    ) -> Result<PublishPrekeyReport, Box<dyn std::error::Error + Send + Sync>> {
        // FileStore is dev-only; do not persist prekeys. The relay's prekey
        // routes assume the production SqliteStore.
        Ok(PublishPrekeyReport {
            inserted: bundle.one_time_prekeys.len(),
            skipped: 0,
        })
    }

    async fn claim_one_time_prekey(
        &self,
        _identity_id: &str,
    ) -> Result<Option<ClaimedPrekey>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join(safe_name(recipient_id));
        let mut out = Vec::new();

        if !tokio::fs::try_exists(&dir).await? {
            return Ok(out);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) == Some("json") {
                let envelope_id = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .unwrap_or_default()
                    .to_string();
                if !envelope_id.is_empty() {
                    let ack_path = self.ack_path(recipient_id, &envelope_id);
                    if tokio::fs::try_exists(&ack_path).await? {
                        continue;
                    }
                }
                let raw = tokio::fs::read_to_string(path).await?;
                let envelope: Envelope = serde_json::from_str(&raw)?;
                if is_expired(&envelope) {
                    // Opportunistic cleanup in file-backed mode.
                    let _ = tokio::fs::remove_file(entry.path()).await;
                    continue;
                }
                out.push(envelope);
            }
        }

        Ok(out)
    }

    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_path = self.envelope_path(recipient_id, envelope_id);
        if !tokio::fs::try_exists(&envelope_path).await? {
            return Ok(LifecycleOutcome::NotFound);
        }

        let ack_path = self.ack_path(recipient_id, envelope_id);
        if let Some(parent) = ack_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(ack_path, b"acknowledged\n").await?;
        Ok(LifecycleOutcome::Acknowledged)
    }

    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_path = self.envelope_path(recipient_id, envelope_id);
        if !tokio::fs::try_exists(&envelope_path).await? {
            return Ok(LifecycleOutcome::NotFound);
        }
        tokio::fs::remove_file(&envelope_path).await?;

        let ack_path = self.ack_path(recipient_id, envelope_id);
        if tokio::fs::try_exists(&ack_path).await? {
            let _ = tokio::fs::remove_file(ack_path).await;
        }
        Ok(LifecycleOutcome::Deleted)
    }

    async fn cleanup(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>> {
        let mut report = CleanupReport {
            expired_removed: 0,
            orphan_ack_removed: 0,
            old_removed: 0,
        };
        if !tokio::fs::try_exists(&self.base).await? {
            return Ok(report);
        }

        let mut recipient_dirs = tokio::fs::read_dir(&self.base).await?;
        while let Some(recipient_entry) = recipient_dirs.next_entry().await? {
            let recipient_path = recipient_entry.path();
            if !recipient_path.is_dir() {
                continue;
            }
            let mut files = tokio::fs::read_dir(&recipient_path).await?;
            while let Some(file_entry) = files.next_entry().await? {
                let path = file_entry.path();
                match path.extension().and_then(|v| v.to_str()) {
                    Some("json") => {
                        let raw = tokio::fs::read_to_string(&path).await?;
                        let envelope: Envelope = serde_json::from_str(&raw)?;
                        if is_expired(&envelope) {
                            let _ = tokio::fs::remove_file(&path).await;
                            report.expired_removed += 1;
                            continue;
                        }
                        if let Some(max_age_days) = policy.max_message_age_days {
                            if envelope.created_at
                                <= (Utc::now() - chrono::Duration::days(max_age_days))
                            {
                                let _ = tokio::fs::remove_file(&path).await;
                                report.old_removed += 1;
                            }
                        }
                    }
                    Some("ack") => {
                        let stem = path
                            .file_stem()
                            .and_then(|v| v.to_str())
                            .unwrap_or_default();
                        if stem.is_empty() {
                            continue;
                        }
                        let envelope_path = recipient_path.join(format!("{stem}.json"));
                        if !tokio::fs::try_exists(envelope_path).await? {
                            let _ = tokio::fs::remove_file(&path).await;
                            report.orphan_ack_removed += 1;
                        }
                    }
                    _ => {}
                }
            }
        }

        Ok(report)
    }

    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join("identities");
        tokio::fs::create_dir_all(&dir).await?;
        let safe = safe_name(&doc.identity_id.0);
        let path = dir.join(format!("{safe}.json"));
        tokio::fs::write(path, serde_json::to_vec_pretty(doc)?).await?;
        Ok(())
    }

    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join("identities");
        let path = dir.join(format!("{}.json", safe_name(identity_id)));
        if !tokio::fs::try_exists(&path).await? {
            return Ok(None);
        }
        let raw = tokio::fs::read_to_string(path).await?;
        Ok(Some(serde_json::from_str(&raw)?))
    }

    async fn resolve_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let dir = self.base.join("identities");
        if !tokio::fs::try_exists(&dir).await? {
            return Ok(None);
        }

        let mut entries = tokio::fs::read_dir(dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let raw = tokio::fs::read_to_string(path).await?;
            let doc: IdentityDocument = serde_json::from_str(&raw)?;
            if doc.aliases.iter().any(|a| a == alias) {
                return Ok(Some(doc));
            }
        }

        Ok(None)
    }

    async fn metrics(&self) -> Result<RelayMetrics, Box<dyn std::error::Error + Send + Sync>> {
        let mut envelopes_total = 0usize;
        let mut envelopes_acknowledged = 0usize;
        let mut identities_total = 0usize;

        if tokio::fs::try_exists(&self.base).await? {
            let mut recipient_dirs = tokio::fs::read_dir(&self.base).await?;
            while let Some(recipient_entry) = recipient_dirs.next_entry().await? {
                let recipient_path = recipient_entry.path();
                if !recipient_path.is_dir() {
                    continue;
                }
                if recipient_path.file_name().and_then(|v| v.to_str()) == Some("identities") {
                    let mut identity_files = tokio::fs::read_dir(&recipient_path).await?;
                    while let Some(identity_entry) = identity_files.next_entry().await? {
                        let path = identity_entry.path();
                        if path.extension().and_then(|v| v.to_str()) == Some("json") {
                            identities_total += 1;
                        }
                    }
                    continue;
                }
                let mut files = tokio::fs::read_dir(&recipient_path).await?;
                while let Some(file_entry) = files.next_entry().await? {
                    let path = file_entry.path();
                    if path.extension().and_then(|v| v.to_str()) == Some("json") {
                        envelopes_total += 1;
                    } else if path.extension().and_then(|v| v.to_str()) == Some("ack") {
                        envelopes_acknowledged += 1;
                    }
                }
            }
        }
        let envelopes_active = envelopes_total.saturating_sub(envelopes_acknowledged);
        Ok(RelayMetrics {
            envelopes_total,
            envelopes_acknowledged,
            envelopes_active,
            identities_total,
        })
    }

    async fn list_identities(
        &self,
        _offset: usize,
        _limit: usize,
    ) -> Result<Vec<IdentityListEntry>, Box<dyn std::error::Error + Send + Sync>> {
        // FileStore is a dev scaffold — pagination not implemented.
        Ok(vec![])
    }

    async fn list_served_domains(
        &self,
        _offset: usize,
        _limit: usize,
    ) -> Result<Vec<DomainEntry>, Box<dyn std::error::Error + Send + Sync>> {
        // FileStore is a dev scaffold — domains aren't persisted here.
        Ok(vec![])
    }

    async fn count_served_domains(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0)
    }

    async fn add_served_domain(
        &self,
        domain: &str,
        verification_token: &str,
    ) -> Result<DomainEntry, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DomainEntry {
            domain: domain.to_string(),
            verification_token: verification_token.to_string(),
            verified_at: None,
            added_at: Utc::now().to_rfc3339(),
        })
    }

    async fn get_served_domain(
        &self,
        _domain: &str,
    ) -> Result<Option<DomainEntry>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn mark_domain_verified(
        &self,
        _domain: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }

    async fn release_served_domain(
        &self,
        _domain: &str,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        Ok(0)
    }

    async fn has_served_domains(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }

    async fn list_provisioned_users(
        &self,
        _domain_filter: Option<&str>,
        _offset: usize,
        _limit: usize,
    ) -> Result<Vec<ProvisionedUserEntry>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![])
    }

    async fn provision_user(
        &self,
        _alias: &str,
    ) -> Result<ProvisionOutcome, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ProvisionOutcome::DomainNotServed)
    }

    async fn deprovision_user(
        &self,
        _alias: &str,
    ) -> Result<DeprovisionOutcome, Box<dyn std::error::Error + Send + Sync>> {
        Ok(DeprovisionOutcome {
            alias_removed: false,
            envelopes_purged: 0,
        })
    }

    async fn claim_provisioned_alias(
        &self,
        _alias: &str,
        _identity_id: &str,
    ) -> Result<ClaimAliasOutcome, Box<dyn std::error::Error + Send + Sync>> {
        Ok(ClaimAliasOutcome::NotProvisioned)
    }

    // FileStore is a dev scaffold and does not implement federation.

    async fn fetch_envelope_json(
        &self,
        _envelope_id: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn enqueue_outbound_delivery(
        &self,
        _envelope_id: &str,
        _target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn next_pending_delivery(
        &self,
    ) -> Result<Option<OutboundDelivery>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn mark_delivery_attempt(
        &self,
        _envelope_id: &str,
        _target_url: &str,
        _error: &str,
        _next_retry_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn mark_delivery_delivered(
        &self,
        _envelope_id: &str,
        _target_url: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(Vec::new())
    }

    async fn mark_delivery_expired(
        &self,
        _envelope_id: &str,
        _target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn federation_metrics(
        &self,
        _window_seconds: i64,
    ) -> Result<FederationMetricsSnapshot, Box<dyn std::error::Error + Send + Sync>> {
        Ok(FederationMetricsSnapshot {
            queue: QueueStats::default(),
            targets: Vec::new(),
        })
    }

    async fn load_relay_identity(
        &self,
    ) -> Result<Option<RelayIdentity>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(None)
    }

    async fn save_relay_identity(
        &self,
        _identity: &RelayIdentity,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    async fn save_delivery_receipt(
        &self,
        _envelope_id: &str,
        _target_url: &str,
        _receipt_json: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SqliteStore
// ---------------------------------------------------------------------------

const MIGRATIONS: &str = "
    PRAGMA journal_mode=WAL;
    CREATE TABLE IF NOT EXISTS envelopes (
        envelope_id TEXT PRIMARY KEY,
        recipient_id TEXT NOT NULL,
        envelope_json TEXT NOT NULL,
        expires_at TEXT,
        acknowledged INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_envelopes_recipient
        ON envelopes(recipient_id);
    CREATE TABLE IF NOT EXISTS identities (
        identity_id TEXT PRIMARY KEY,
        identity_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS identity_aliases (
        alias TEXT NOT NULL,
        identity_id TEXT NOT NULL,
        PRIMARY KEY (alias)
    );
    CREATE INDEX IF NOT EXISTS idx_identity_aliases_identity_id
        ON identity_aliases(identity_id);
    CREATE TABLE IF NOT EXISTS consumed_prekeys (
        recipient_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        consumed_at TEXT NOT NULL,
        envelope_id TEXT NOT NULL,
        PRIMARY KEY (recipient_id, key_id)
    );
    CREATE TABLE IF NOT EXISTS one_time_prekeys (
        identity_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        algorithm TEXT NOT NULL,
        public_key_b64 TEXT NOT NULL,
        bundle_signature TEXT NOT NULL,
        published_at TEXT NOT NULL,
        claimed INTEGER NOT NULL DEFAULT 0,
        claimed_at TEXT,
        PRIMARY KEY (identity_id, key_id)
    );
    CREATE INDEX IF NOT EXISTS idx_one_time_prekeys_unclaimed
        ON one_time_prekeys(identity_id, claimed);
    CREATE TABLE IF NOT EXISTS served_domains (
        domain TEXT PRIMARY KEY,
        verification_token TEXT NOT NULL,
        verified_at TEXT,
        added_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS provisioned_users (
        alias TEXT PRIMARY KEY,
        identity_id TEXT,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_provisioned_users_identity_id
        ON provisioned_users(identity_id);

    -- Phase 5 federation queue (mlaify/aegis-relay#28). One row per
    -- (envelope, target relay) pair. Status flows pending → delivered |
    -- expired | superseded (#30). Receipt_json (#32) starts NULL and
    -- gets populated when a peer returns a signed delivery receipt.
    -- The composite PK keeps `enqueue_outbound_delivery` idempotent
    -- without a separate UNIQUE constraint.
    CREATE TABLE IF NOT EXISTS outbound_deliveries (
        envelope_id TEXT NOT NULL,
        target_url TEXT NOT NULL,
        status TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_retry_at TEXT NOT NULL,
        last_error TEXT,
        last_attempt_at TEXT,
        created_at TEXT NOT NULL,
        delivered_at TEXT,
        receipt_json TEXT,
        PRIMARY KEY (envelope_id, target_url)
    );
    CREATE INDEX IF NOT EXISTS idx_outbound_deliveries_due
        ON outbound_deliveries(status, next_retry_at);

    -- Phase 6 federation auth (#32): the relay's own hybrid identity,
    -- used to sign delivery receipts. Single-row table — keyed on
    -- `slot='primary'` so future rotation can introduce 'next' / 'old'
    -- slots without a schema change. `secrets_json` is the
    -- HybridPqPrivateKeyMaterial JSON; `document_json` is the SIGNED
    -- IdentityDocument JSON published via /.well-known/aegis-config.
    CREATE TABLE IF NOT EXISTS relay_identity (
        slot TEXT PRIMARY KEY,
        identity_id TEXT NOT NULL,
        document_json TEXT NOT NULL,
        secrets_json TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
";

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    pub async fn open(path: &str) -> Result<Self, tokio_rusqlite::Error> {
        let conn = Connection::open(path).await?;
        conn.call(|c| {
            c.execute_batch(MIGRATIONS)?;
            run_post_init_migrations(c)?;
            Ok(())
        })
        .await?;
        Ok(Self { conn })
    }

    #[allow(dead_code)]
    pub async fn open_in_memory() -> Result<Self, tokio_rusqlite::Error> {
        let conn = Connection::open_in_memory().await?;
        conn.call(|c| {
            c.execute_batch(MIGRATIONS)?;
            run_post_init_migrations(c)?;
            Ok(())
        })
        .await?;
        Ok(Self { conn })
    }
}

/// Idempotent migrations that don't fit the "CREATE TABLE IF NOT EXISTS"
/// pattern — primarily, `ALTER TABLE ADD COLUMN` for columns we added
/// after a table was originally shipped. SQLite has no native
/// `ADD COLUMN IF NOT EXISTS`, so we feature-detect via `pragma_table_info`
/// and only ALTER when the column's missing.
fn run_post_init_migrations(c: &rusqlite::Connection) -> rusqlite::Result<()> {
    add_column_if_missing(
        c,
        "outbound_deliveries",
        "receipt_json",
        "ALTER TABLE outbound_deliveries ADD COLUMN receipt_json TEXT",
    )?;
    Ok(())
}

fn add_column_if_missing(
    c: &rusqlite::Connection,
    table: &str,
    column: &str,
    alter_sql: &str,
) -> rusqlite::Result<()> {
    let mut stmt = c.prepare(&format!(
        "SELECT 1 FROM pragma_table_info('{}') WHERE name = ?1",
        table
    ))?;
    let present = stmt.exists(rusqlite::params![column])?;
    drop(stmt);
    if !present {
        c.execute(alter_sql, [])?;
    }
    Ok(())
}

#[async_trait]
impl Store for SqliteStore {
    async fn store(
        &self,
        envelope: &Envelope,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(envelope)?;
        let envelope_id = envelope.envelope_id.0.to_string();
        let recipient_id = envelope.recipient_id.0.clone();
        // Store in SQLite datetime format ("YYYY-MM-DD HH:MM:SS" UTC) so that
        // comparisons against datetime('now') work as plain string comparisons.
        let expires_at = envelope
            .expires_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string());
        self.conn
            .call(move |c| {
                c.execute(
                    "INSERT OR REPLACE INTO envelopes \
                     (envelope_id, recipient_id, envelope_json, expires_at, acknowledged) \
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    rusqlite::params![envelope_id, recipient_id, json, expires_at],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn store_with_prekey_consumption(
        &self,
        envelope: &Envelope,
    ) -> Result<StoreOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let json = serde_json::to_string(envelope)?;
        let envelope_id = envelope.envelope_id.0.to_string();
        let recipient_id = envelope.recipient_id.0.clone();
        let expires_at = envelope
            .expires_at
            .map(|t| t.format("%Y-%m-%d %H:%M:%S").to_string());
        let used_prekey_ids = envelope.used_prekey_ids.clone();
        let consumed_at = Utc::now().to_rfc3339();
        let outcome = self
            .conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                for key_id in &used_prekey_ids {
                    // (v0.3 phase 2) Verify the prekey was actually published
                    // for this recipient. Same transaction so a concurrent
                    // publish/claim cannot race us.
                    let exists: Option<i64> = tx
                        .query_row(
                            "SELECT 1 FROM one_time_prekeys \
                             WHERE identity_id = ?1 AND key_id = ?2",
                            rusqlite::params![recipient_id, key_id],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if exists.is_none() {
                        return Ok(StoreOutcome::UnknownPrekey {
                            key_id: key_id.clone(),
                        });
                    }

                    let res = tx.execute(
                        "INSERT INTO consumed_prekeys \
                         (recipient_id, key_id, consumed_at, envelope_id) \
                         VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![recipient_id, key_id, consumed_at, envelope_id],
                    );
                    match res {
                        Ok(_) => {}
                        Err(rusqlite::Error::SqliteFailure(err, _))
                            if err.code == rusqlite::ErrorCode::ConstraintViolation =>
                        {
                            // Drop tx without commit -> rollback.
                            return Ok(StoreOutcome::PrekeyAlreadyUsed {
                                key_id: key_id.clone(),
                            });
                        }
                        Err(e) => return Err(e.into()),
                    }
                }
                tx.execute(
                    "INSERT OR REPLACE INTO envelopes \
                     (envelope_id, recipient_id, envelope_json, expires_at, acknowledged) \
                     VALUES (?1, ?2, ?3, ?4, 0)",
                    rusqlite::params![envelope_id, recipient_id, json, expires_at],
                )?;
                tx.commit()?;
                Ok(StoreOutcome::Stored)
            })
            .await?;
        Ok(outcome)
    }

    async fn fetch(
        &self,
        recipient_id: &str,
    ) -> Result<Vec<Envelope>, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let rows: Vec<String> = self
            .conn
            .call(move |c| {
                let mut stmt = c.prepare(
                    "SELECT envelope_json FROM envelopes \
                     WHERE recipient_id = ?1 AND acknowledged = 0 \
                     AND (expires_at IS NULL OR expires_at > datetime('now'))",
                )?;
                let result = stmt
                    .query_map(rusqlite::params![recipient_id], |row| {
                        row.get::<_, String>(0)
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e: rusqlite::Error| e.into());
                result
            })
            .await?;
        rows.into_iter()
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
            })
            .collect()
    }

    async fn acknowledge(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let envelope_id = envelope_id.to_string();
        let rows_changed = self
            .conn
            .call(move |c| {
                c.execute(
                    "UPDATE envelopes SET acknowledged = 1 \
                     WHERE envelope_id = ?1 AND recipient_id = ?2",
                    rusqlite::params![envelope_id, recipient_id],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(if rows_changed == 0 {
            LifecycleOutcome::NotFound
        } else {
            LifecycleOutcome::Acknowledged
        })
    }

    async fn delete(
        &self,
        recipient_id: &str,
        envelope_id: &str,
    ) -> Result<LifecycleOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let recipient_id = recipient_id.to_string();
        let envelope_id = envelope_id.to_string();
        let rows_changed = self
            .conn
            .call(move |c| {
                c.execute(
                    "DELETE FROM envelopes WHERE envelope_id = ?1 AND recipient_id = ?2",
                    rusqlite::params![envelope_id, recipient_id],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(if rows_changed == 0 {
            LifecycleOutcome::NotFound
        } else {
            LifecycleOutcome::Deleted
        })
    }

    async fn cleanup(
        &self,
        policy: &RetentionPolicy,
    ) -> Result<CleanupReport, Box<dyn std::error::Error + Send + Sync>> {
        let max_age_days = policy.max_message_age_days;
        let purge_acked = policy.purge_acknowledged_on_cleanup;
        let (expired_removed, orphan_ack_removed, old_removed) = self
            .conn
            .call(move |c| {
                let expired = c.execute(
                    "DELETE FROM envelopes \
                     WHERE expires_at IS NOT NULL AND expires_at <= datetime('now')",
                    [],
                )?;
                let acked = if purge_acked {
                    c.execute("DELETE FROM envelopes WHERE acknowledged = 1", [])?
                } else {
                    0
                };
                let old = if let Some(days) = max_age_days {
                    c.execute(
                        "DELETE FROM envelopes
                         WHERE datetime(json_extract(envelope_json, '$.created_at')) <= datetime('now', ?1)",
                        rusqlite::params![format!("-{} days", days)],
                    )?
                } else {
                    0
                };
                Ok((expired, acked, old))
            })
            .await?;
        Ok(CleanupReport {
            expired_removed,
            orphan_ack_removed,
            old_removed,
        })
    }

    async fn store_identity(
        &self,
        doc: &IdentityDocument,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = doc.identity_id.0.clone();
        let json = serde_json::to_string(doc)?;
        let updated_at = Utc::now().to_rfc3339();
        let aliases = doc.aliases.clone();
        self.conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                tx.execute(
                    "INSERT OR REPLACE INTO identities \
                     (identity_id, identity_json, updated_at) VALUES (?1, ?2, ?3)",
                    rusqlite::params![identity_id, json, updated_at],
                )?;
                // Rebuild alias index for this identity atomically.
                tx.execute(
                    "DELETE FROM identity_aliases WHERE identity_id = ?1",
                    rusqlite::params![identity_id],
                )?;
                for alias in &aliases {
                    tx.execute(
                        "INSERT OR REPLACE INTO identity_aliases (alias, identity_id) \
                         VALUES (?1, ?2)",
                        rusqlite::params![alias, identity_id],
                    )?;
                }
                tx.commit().map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn fetch_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = identity_id.to_string();
        let result: Option<String> = self
            .conn
            .call(move |c| {
                c.query_row(
                    "SELECT identity_json FROM identities WHERE identity_id = ?1",
                    rusqlite::params![identity_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        match result {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn resolve_alias(
        &self,
        alias: &str,
    ) -> Result<Option<IdentityDocument>, Box<dyn std::error::Error + Send + Sync>> {
        let alias = alias.to_string();
        let result: Option<String> = self
            .conn
            .call(move |c| {
                c.query_row(
                    "SELECT i.identity_json \
                     FROM identities i \
                     JOIN identity_aliases a ON a.identity_id = i.identity_id \
                     WHERE a.alias = ?1 \
                     LIMIT 1",
                    rusqlite::params![alias],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        match result {
            Some(json) => Ok(Some(serde_json::from_str(&json)?)),
            None => Ok(None),
        }
    }

    async fn metrics(&self) -> Result<RelayMetrics, Box<dyn std::error::Error + Send + Sync>> {
        let (envelopes_total, envelopes_acknowledged, envelopes_active, identities_total) = self
            .conn
            .call(|c| {
                let total: i64 = c.query_row("SELECT COUNT(*) FROM envelopes", [], |r| r.get(0))?;
                let acked: i64 = c.query_row(
                    "SELECT COUNT(*) FROM envelopes WHERE acknowledged = 1",
                    [],
                    |r| r.get(0),
                )?;
                let active: i64 = c.query_row(
                    "SELECT COUNT(*) FROM envelopes WHERE acknowledged = 0",
                    [],
                    |r| r.get(0),
                )?;
                let identities: i64 =
                    c.query_row("SELECT COUNT(*) FROM identities", [], |r| r.get(0))?;
                Ok((total, acked, active, identities))
            })
            .await?;
        Ok(RelayMetrics {
            envelopes_total: envelopes_total as usize,
            envelopes_acknowledged: envelopes_acknowledged as usize,
            envelopes_active: envelopes_active as usize,
            identities_total: identities_total as usize,
        })
    }

    async fn store_one_time_prekeys(
        &self,
        bundle: &PrekeyBundle,
    ) -> Result<PublishPrekeyReport, Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = bundle.identity_id.0.clone();
        let signature = bundle.signature.clone().ok_or_else(
            || -> Box<dyn std::error::Error + Send + Sync> { "prekey bundle is unsigned".into() },
        )?;
        let entries: Vec<(String, String, String)> = bundle
            .one_time_prekeys
            .iter()
            .map(|k| {
                (
                    k.key_id.clone(),
                    k.algorithm.clone(),
                    k.public_key_b64.clone(),
                )
            })
            .collect();
        let published_at = Utc::now().to_rfc3339();
        let report = self
            .conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                let mut inserted = 0usize;
                let mut skipped = 0usize;
                for (key_id, algorithm, public_key_b64) in &entries {
                    // INSERT OR IGNORE: re-publishing a partially-consumed
                    // bundle is idempotent and does NOT reset claimed=1 on
                    // already-consumed entries.
                    let rows = tx.execute(
                        "INSERT OR IGNORE INTO one_time_prekeys \
                         (identity_id, key_id, algorithm, public_key_b64, \
                          bundle_signature, published_at) \
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        rusqlite::params![
                            identity_id,
                            key_id,
                            algorithm,
                            public_key_b64,
                            signature,
                            published_at
                        ],
                    )?;
                    if rows == 1 {
                        inserted += 1;
                    } else {
                        skipped += 1;
                    }
                }
                tx.commit()?;
                Ok(PublishPrekeyReport { inserted, skipped })
            })
            .await?;
        Ok(report)
    }

    async fn claim_one_time_prekey(
        &self,
        identity_id: &str,
    ) -> Result<Option<ClaimedPrekey>, Box<dyn std::error::Error + Send + Sync>> {
        let identity_id = identity_id.to_string();
        let claimed_at = Utc::now().to_rfc3339();
        let claimed = self
            .conn
            .call(move |c| {
                let tx = c.unchecked_transaction()?;
                // Pick one unclaimed prekey for this identity.
                let pick: Option<(String, String, String)> = tx
                    .query_row(
                        "SELECT key_id, algorithm, public_key_b64 \
                         FROM one_time_prekeys \
                         WHERE identity_id = ?1 AND claimed = 0 \
                         ORDER BY published_at ASC, key_id ASC \
                         LIMIT 1",
                        rusqlite::params![identity_id],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .optional()?;
                let Some((key_id, algorithm, public_key_b64)) = pick else {
                    tx.commit()?;
                    return Ok(None);
                };
                // Mark it claimed under the same transaction.
                let updated = tx.execute(
                    "UPDATE one_time_prekeys \
                     SET claimed = 1, claimed_at = ?3 \
                     WHERE identity_id = ?1 AND key_id = ?2 AND claimed = 0",
                    rusqlite::params![identity_id, key_id, claimed_at],
                )?;
                if updated != 1 {
                    // Lost a race; bail without committing.
                    return Ok(None);
                }
                tx.commit()?;
                Ok(Some(ClaimedPrekey {
                    identity_id: identity_id.clone(),
                    key_id,
                    algorithm,
                    public_key_b64,
                }))
            })
            .await?;
        Ok(claimed)
    }

    async fn list_identities(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<IdentityListEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let rows = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT identity_id, identity_json, updated_at \
                     FROM identities \
                     ORDER BY updated_at DESC \
                     LIMIT ?1 OFFSET ?2",
                )?;
                let rows = stmt
                    .query_map(
                        rusqlite::params![limit as i64, offset as i64],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;

        let entries = rows
            .into_iter()
            .map(|(identity_id, identity_json, updated_at)| {
                let aliases = serde_json::from_str::<aegis_proto::IdentityDocument>(&identity_json)
                    .map(|doc| doc.aliases)
                    .unwrap_or_default();
                IdentityListEntry {
                    identity_id,
                    aliases,
                    updated_at,
                }
            })
            .collect();

        Ok(entries)
    }

    async fn list_served_domains(
        &self,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<DomainEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let offset_i64 = offset as i64;
        let limit_i64 = limit as i64;
        let rows = self
            .conn
            .call(move |conn| {
                let mut stmt = conn.prepare(
                    "SELECT domain, verification_token, verified_at, added_at \
                     FROM served_domains \
                     ORDER BY added_at ASC \
                     LIMIT ?1 OFFSET ?2",
                )?;
                let rows = stmt
                    .query_map(rusqlite::params![limit_i64, offset_i64], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, String>(1)?,
                            row.get::<_, Option<String>>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(rows)
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|(domain, verification_token, verified_at, added_at)| DomainEntry {
                domain,
                verification_token,
                verified_at,
                added_at,
            })
            .collect())
    }

    async fn count_served_domains(
        &self,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let n: i64 = self
            .conn
            .call(|conn| {
                conn.query_row("SELECT COUNT(*) FROM served_domains", [], |row| row.get(0))
                    .map_err(|e| e.into())
            })
            .await?;
        Ok(n.max(0) as usize)
    }

    async fn add_served_domain(
        &self,
        domain: &str,
        verification_token: &str,
    ) -> Result<DomainEntry, Box<dyn std::error::Error + Send + Sync>> {
        let domain_owned = domain.to_string();
        let token_owned = verification_token.to_string();
        let added_at = Utc::now().to_rfc3339();
        let entry = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;
                let existing = tx
                    .query_row(
                        "SELECT verification_token, verified_at, added_at \
                         FROM served_domains WHERE domain = ?1",
                        rusqlite::params![domain_owned],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, Option<String>>(1)?,
                                row.get::<_, String>(2)?,
                            ))
                        },
                    )
                    .optional()?;
                let entry = if let Some((token, verified_at, added)) = existing {
                    DomainEntry {
                        domain: domain_owned.clone(),
                        verification_token: token,
                        verified_at,
                        added_at: added,
                    }
                } else {
                    tx.execute(
                        "INSERT INTO served_domains \
                         (domain, verification_token, verified_at, added_at) \
                         VALUES (?1, ?2, NULL, ?3)",
                        rusqlite::params![domain_owned, token_owned, added_at],
                    )?;
                    DomainEntry {
                        domain: domain_owned.clone(),
                        verification_token: token_owned,
                        verified_at: None,
                        added_at,
                    }
                };
                tx.commit()?;
                Ok(entry)
            })
            .await?;
        Ok(entry)
    }

    async fn get_served_domain(
        &self,
        domain: &str,
    ) -> Result<Option<DomainEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let domain_owned = domain.to_string();
        let row = self
            .conn
            .call(move |conn| {
                let row = conn
                    .query_row(
                        "SELECT domain, verification_token, verified_at, added_at \
                         FROM served_domains WHERE domain = ?1",
                        rusqlite::params![domain_owned],
                        |row| {
                            Ok((
                                row.get::<_, String>(0)?,
                                row.get::<_, String>(1)?,
                                row.get::<_, Option<String>>(2)?,
                                row.get::<_, String>(3)?,
                            ))
                        },
                    )
                    .optional()?;
                Ok(row)
            })
            .await?;
        Ok(row.map(|(domain, verification_token, verified_at, added_at)| DomainEntry {
            domain,
            verification_token,
            verified_at,
            added_at,
        }))
    }

    async fn mark_domain_verified(
        &self,
        domain: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let domain_owned = domain.to_string();
        let verified_at = Utc::now().to_rfc3339();
        let n = self
            .conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE served_domains SET verified_at = ?1 WHERE domain = ?2",
                    rusqlite::params![verified_at, domain_owned],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(n > 0)
    }

    async fn release_served_domain(
        &self,
        domain: &str,
    ) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
        let domain_owned = domain.to_string();
        let suffix = format!("@{}", domain_owned);
        let removed = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;
                let aliases_removed = tx.execute(
                    "DELETE FROM identity_aliases \
                     WHERE alias LIKE ?1 ESCAPE '\\'",
                    rusqlite::params![format!("%{}", escape_like(&suffix))],
                )?;
                tx.execute(
                    "DELETE FROM provisioned_users \
                     WHERE alias LIKE ?1 ESCAPE '\\'",
                    rusqlite::params![format!("%{}", escape_like(&suffix))],
                )?;
                tx.execute(
                    "DELETE FROM served_domains WHERE domain = ?1",
                    rusqlite::params![domain_owned],
                )?;
                tx.commit()?;
                Ok(aliases_removed)
            })
            .await?;
        Ok(removed)
    }

    async fn has_served_domains(
        &self,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let count: i64 = self
            .conn
            .call(|conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM served_domains WHERE verified_at IS NOT NULL",
                    [],
                    |row| row.get(0),
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(count > 0)
    }

    async fn list_provisioned_users(
        &self,
        domain_filter: Option<&str>,
        offset: usize,
        limit: usize,
    ) -> Result<Vec<ProvisionedUserEntry>, Box<dyn std::error::Error + Send + Sync>> {
        let filter_owned = domain_filter.map(|s| format!("%@{}", escape_like(s)));
        let rows = self
            .conn
            .call(move |conn| {
                let map_row = |row: &rusqlite::Row<'_>| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                };
                if let Some(pattern) = filter_owned {
                    let mut stmt = conn.prepare(
                        "SELECT alias, identity_id, status, created_at, updated_at \
                         FROM provisioned_users \
                         WHERE alias LIKE ?1 ESCAPE '\\' \
                         ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                    )?;
                    let rows = stmt
                        .query_map(
                            rusqlite::params![pattern, limit as i64, offset as i64],
                            map_row,
                        )?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                } else {
                    let mut stmt = conn.prepare(
                        "SELECT alias, identity_id, status, created_at, updated_at \
                         FROM provisioned_users \
                         ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
                    )?;
                    let rows = stmt
                        .query_map(rusqlite::params![limit as i64, offset as i64], map_row)?
                        .collect::<Result<Vec<_>, _>>()?;
                    Ok(rows)
                }
            })
            .await?;
        Ok(rows
            .into_iter()
            .map(|(alias, identity_id, status, created_at, updated_at)| ProvisionedUserEntry {
                alias,
                identity_id,
                status,
                created_at,
                updated_at,
            })
            .collect())
    }

    async fn provision_user(
        &self,
        alias: &str,
    ) -> Result<ProvisionOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let domain = match alias.split_once('@') {
            Some((_, d)) if !d.is_empty() => d.to_string(),
            _ => return Ok(ProvisionOutcome::DomainNotServed),
        };
        let alias_owned = alias.to_string();
        let now = Utc::now().to_rfc3339();
        let outcome = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;
                let domain_ok: Option<i64> = tx
                    .query_row(
                        "SELECT 1 FROM served_domains \
                         WHERE domain = ?1 AND verified_at IS NOT NULL",
                        rusqlite::params![domain],
                        |row| row.get(0),
                    )
                    .optional()?;
                if domain_ok.is_none() {
                    return Ok(ProvisionOutcome::DomainNotServed);
                }
                let exists: Option<i64> = tx
                    .query_row(
                        "SELECT 1 FROM provisioned_users WHERE alias = ?1",
                        rusqlite::params![alias_owned],
                        |row| row.get(0),
                    )
                    .optional()?;
                if exists.is_some() {
                    return Ok(ProvisionOutcome::AlreadyExists);
                }
                tx.execute(
                    "INSERT INTO provisioned_users \
                     (alias, identity_id, status, created_at, updated_at) \
                     VALUES (?1, NULL, 'provisioned', ?2, ?2)",
                    rusqlite::params![alias_owned, now],
                )?;
                tx.commit()?;
                Ok(ProvisionOutcome::Created)
            })
            .await?;
        Ok(outcome)
    }

    async fn deprovision_user(
        &self,
        alias: &str,
    ) -> Result<DeprovisionOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let alias_owned = alias.to_string();
        // One transaction so the alias deletion and envelope purge are
        // atomic — partial failure can't leave a stale alias pointing at
        // an empty inbox or vice-versa.
        let outcome = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;

                // Look up the bound identity_id BEFORE deleting any rows.
                // We read from `provisioned_users` because that is the
                // canonical source-of-truth in managed mode: when an
                // identity claims a provisioned alias, `claim_provisioned_alias`
                // writes `identity_id` here. The mirror row in
                // `identity_aliases` may or may not exist (it lives on
                // the identity PUT path); `provisioned_users` is always
                // current. A `Some(None)` result means the alias was
                // provisioned but never claimed — nothing to purge.
                let identity_id: Option<String> = tx
                    .query_row(
                        "SELECT identity_id FROM provisioned_users WHERE alias = ?1",
                        rusqlite::params![alias_owned],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten();

                let alias_removed_count = tx.execute(
                    "DELETE FROM provisioned_users WHERE alias = ?1",
                    rusqlite::params![alias_owned],
                )?;
                tx.execute(
                    "DELETE FROM identity_aliases WHERE alias = ?1",
                    rusqlite::params![alias_owned],
                )?;

                // Only purge envelopes when the alias was bound to an
                // identity. Envelopes are addressed by `recipient_id` —
                // the underlying identity_id — so the alias-to-identity
                // mapping is the bridge between "deprovision user@domain"
                // and "drop their inbox queue".
                let envelopes_purged = if let Some(ref id) = identity_id {
                    tx.execute(
                        "DELETE FROM envelopes WHERE recipient_id = ?1",
                        rusqlite::params![id],
                    )? as u64
                } else {
                    0u64
                };

                tx.commit()?;
                Ok((alias_removed_count > 0, envelopes_purged))
            })
            .await?;
        Ok(DeprovisionOutcome {
            alias_removed: outcome.0,
            envelopes_purged: outcome.1,
        })
    }

    async fn claim_provisioned_alias(
        &self,
        alias: &str,
        identity_id: &str,
    ) -> Result<ClaimAliasOutcome, Box<dyn std::error::Error + Send + Sync>> {
        let alias_owned = alias.to_string();
        let identity_owned = identity_id.to_string();
        let now = Utc::now().to_rfc3339();
        let outcome = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;
                let row: Option<Option<String>> = tx
                    .query_row(
                        "SELECT identity_id FROM provisioned_users WHERE alias = ?1",
                        rusqlite::params![alias_owned],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()?;
                let outcome = match row {
                    None => ClaimAliasOutcome::NotProvisioned,
                    Some(None) => {
                        tx.execute(
                            "UPDATE provisioned_users \
                             SET identity_id = ?1, status = 'active', updated_at = ?2 \
                             WHERE alias = ?3",
                            rusqlite::params![identity_owned, now, alias_owned],
                        )?;
                        ClaimAliasOutcome::Bound
                    }
                    Some(Some(existing)) if existing == identity_owned => {
                        ClaimAliasOutcome::Bound
                    }
                    Some(Some(other)) => ClaimAliasOutcome::OwnedByOther { identity_id: other },
                };
                tx.commit()?;
                Ok(outcome)
            })
            .await?;
        Ok(outcome)
    }

    // -- Outbound federation queue (#28) -------------------------------------

    async fn fetch_envelope_json(
        &self,
        envelope_id: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let row = self
            .conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT envelope_json FROM envelopes WHERE envelope_id = ?1",
                    rusqlite::params![envelope_id],
                    |r| r.get::<_, String>(0),
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        Ok(row)
    }

    async fn enqueue_outbound_delivery(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let target_url = target_url.to_string();
        let now = Utc::now().to_rfc3339();
        // INSERT OR IGNORE on the composite PK gives us idempotent
        // enqueueing — if (envelope, target) is already in the queue we
        // leave the existing row alone (which preserves attempt count
        // and current backoff state). Federation worker will pick it up
        // again next tick if it's pending.
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO outbound_deliveries \
                     (envelope_id, target_url, status, attempts, next_retry_at, created_at) \
                     VALUES (?1, ?2, 'pending', 0, ?3, ?3)",
                    rusqlite::params![envelope_id, target_url, now],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn next_pending_delivery(
        &self,
    ) -> Result<Option<OutboundDelivery>, Box<dyn std::error::Error + Send + Sync>> {
        let now = Utc::now().to_rfc3339();
        let row = self
            .conn
            .call(move |conn| {
                conn.query_row(
                    "SELECT envelope_id, target_url, status, attempts, next_retry_at, \
                            last_error, last_attempt_at, created_at \
                     FROM outbound_deliveries \
                     WHERE status = 'pending' AND next_retry_at <= ?1 \
                     ORDER BY next_retry_at ASC \
                     LIMIT 1",
                    rusqlite::params![now],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, String>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                            r.get::<_, String>(7)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        Ok(row.map(|t| OutboundDelivery {
            envelope_id: t.0,
            target_url: t.1,
            status: t.2,
            attempts: t.3.max(0) as u32,
            next_retry_at: t.4,
            last_error: t.5,
            last_attempt_at: t.6,
            created_at: t.7,
        }))
    }

    async fn mark_delivery_attempt(
        &self,
        envelope_id: &str,
        target_url: &str,
        error: &str,
        next_retry_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let target_url = target_url.to_string();
        let error = error.to_string();
        let next = next_retry_at.to_rfc3339();
        let now = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE outbound_deliveries \
                     SET attempts = attempts + 1, \
                         last_error = ?1, \
                         last_attempt_at = ?2, \
                         next_retry_at = ?3 \
                     WHERE envelope_id = ?4 AND target_url = ?5 AND status = 'pending'",
                    rusqlite::params![error, now, next, envelope_id, target_url],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn mark_delivery_delivered(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let target_url = target_url.to_string();
        let now = Utc::now().to_rfc3339();
        // One transaction:
        //   1. Snapshot the still-`pending` siblings BEFORE we touch them
        //      (we need the URL list to return so the worker can audit-
        //      log each transition).
        //   2. Flip the winning row to 'delivered'.
        //   3. Flip the siblings to 'superseded'.
        //   4. Drop the local envelope copy.
        // If the transaction fails partway, none of these writes apply
        // and the worker will retry the delivery on the next tick.
        let envelope_for_call = envelope_id.clone();
        let target_for_call = target_url.clone();
        let superseded = self
            .conn
            .call(move |conn| {
                let tx = conn.unchecked_transaction()?;

                // Capture the URLs of pending siblings — same envelope,
                // different target, status still 'pending' — so we can
                // tell the worker exactly which ones we're collapsing.
                let mut stmt = tx.prepare(
                    "SELECT target_url FROM outbound_deliveries \
                     WHERE envelope_id = ?1 AND status = 'pending' AND target_url <> ?2",
                )?;
                let siblings: Vec<String> = stmt
                    .query_map(
                        rusqlite::params![envelope_for_call, target_for_call],
                        |r| r.get::<_, String>(0),
                    )?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(stmt);

                // 2. Mark the winner delivered.
                tx.execute(
                    "UPDATE outbound_deliveries \
                     SET status = 'delivered', \
                         delivered_at = ?1, \
                         last_attempt_at = ?1 \
                     WHERE envelope_id = ?2 AND target_url = ?3",
                    rusqlite::params![now, envelope_for_call, target_for_call],
                )?;

                // 3. Bulk-flip pending siblings to 'superseded' so
                //    `next_pending_delivery` won't return them. We don't
                //    bump `attempts` here — being superseded isn't a
                //    failed attempt.
                tx.execute(
                    "UPDATE outbound_deliveries \
                     SET status = 'superseded', last_attempt_at = ?1 \
                     WHERE envelope_id = ?2 AND status = 'pending' AND target_url <> ?3",
                    rusqlite::params![now, envelope_for_call, target_for_call],
                )?;

                // 4. Drop the local envelope; the recipient's
                //    authoritative relay holds it now.
                tx.execute(
                    "DELETE FROM envelopes WHERE envelope_id = ?1",
                    rusqlite::params![envelope_for_call],
                )?;

                tx.commit()?;
                Ok(siblings)
            })
            .await?;
        Ok(superseded)
    }

    async fn mark_delivery_expired(
        &self,
        envelope_id: &str,
        target_url: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let target_url = target_url.to_string();
        let now = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE outbound_deliveries \
                     SET status = 'expired', last_attempt_at = ?1 \
                     WHERE envelope_id = ?2 AND target_url = ?3",
                    rusqlite::params![now, envelope_id, target_url],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn federation_metrics(
        &self,
        window_seconds: i64,
    ) -> Result<FederationMetricsSnapshot, Box<dyn std::error::Error + Send + Sync>> {
        // Cutoff for the sliding window. Uses chrono so SQLite gets a
        // lexicographically-comparable RFC-3339 string; existing storage
        // columns are stored that way too.
        let cutoff = (Utc::now() - chrono::Duration::seconds(window_seconds)).to_rfc3339();

        // One round-trip pulls everything we need:
        //   - one aggregation query: per-target counts + last_success/last_failure
        //   - one query for percentile computation (raw `attempts` over delivered rows in-window)
        //   - one query for queue-level oldest_pending_age
        // Done in a single `call` to keep the connection-pool usage low
        // and so the snapshot is internally consistent (no torn reads
        // across multiple awaits).
        let snapshot = self
            .conn
            .call(move |conn| {
                // Per-target rollup. SQL takes care of the simple counts;
                // percentiles are done after-the-fact in Rust because
                // SQLite's bundled build doesn't ship percentile_cont.
                let mut rollup_stmt = conn.prepare(
                    "SELECT \
                        target_url, \
                        SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) AS pending, \
                        SUM(CASE WHEN status = 'delivered' AND delivered_at >= ?1 THEN 1 ELSE 0 END) AS delivered_recent, \
                        SUM(CASE WHEN status = 'expired' AND last_attempt_at >= ?1 THEN 1 ELSE 0 END) AS expired_recent, \
                        SUM(CASE WHEN status = 'superseded' AND last_attempt_at >= ?1 THEN 1 ELSE 0 END) AS superseded_recent, \
                        MAX(CASE WHEN status = 'delivered' AND delivered_at >= ?1 THEN delivered_at END) AS last_success_at, \
                        MAX(CASE WHEN status = 'expired' AND last_attempt_at >= ?1 THEN last_attempt_at END) AS last_failure_at \
                     FROM outbound_deliveries \
                     GROUP BY target_url \
                     ORDER BY target_url",
                )?;
                let target_rows: Vec<(
                    String,
                    i64,
                    i64,
                    i64,
                    i64,
                    Option<String>,
                    Option<String>,
                )> = rollup_stmt
                    .query_map(rusqlite::params![cutoff], |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, i64>(1)?,
                            r.get::<_, i64>(2)?,
                            r.get::<_, i64>(3)?,
                            r.get::<_, i64>(4)?,
                            r.get::<_, Option<String>>(5)?,
                            r.get::<_, Option<String>>(6)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(rollup_stmt);

                // Percentile inputs: per-target attempt counts for the
                // delivered rows in-window. Sorted ASC so the percentile
                // calculation in Rust is a direct index lookup.
                let mut attempts_stmt = conn.prepare(
                    "SELECT target_url, attempts FROM outbound_deliveries \
                     WHERE status = 'delivered' AND delivered_at >= ?1 \
                     ORDER BY target_url ASC, attempts ASC",
                )?;
                let attempt_rows: Vec<(String, i64)> = attempts_stmt
                    .query_map(rusqlite::params![&cutoff], |r| {
                        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;
                drop(attempts_stmt);

                // Queue-level totals + oldest_pending_age. Computed from
                // the rollup so we don't double-scan.
                let oldest_pending_at: Option<String> = conn
                    .query_row(
                        "SELECT MIN(created_at) FROM outbound_deliveries WHERE status = 'pending'",
                        [],
                        |r| r.get::<_, Option<String>>(0),
                    )
                    .optional()?
                    .flatten();

                Ok((target_rows, attempt_rows, oldest_pending_at))
            })
            .await?;

        let (target_rows, attempt_rows, oldest_pending_at) = snapshot;

        // Group attempt counts by target_url for percentile compute.
        // attempt_rows is already sorted (target_url ASC, attempts ASC)
        // so we can walk it linearly.
        let mut attempts_by_target: std::collections::HashMap<String, Vec<u32>> =
            std::collections::HashMap::new();
        for (target, n) in attempt_rows {
            attempts_by_target
                .entry(target)
                .or_default()
                .push(n.max(0) as u32);
        }

        let mut targets = Vec::with_capacity(target_rows.len());
        let mut queue = QueueStats::default();
        for (target_url, pending, delivered, expired, superseded, last_success, last_failure) in
            target_rows
        {
            queue.pending += pending.max(0) as u64;
            queue.delivered_recent += delivered.max(0) as u64;
            queue.expired_recent += expired.max(0) as u64;
            queue.superseded_recent += superseded.max(0) as u64;

            let attempts = attempts_by_target
                .get(&target_url)
                .cloned()
                .unwrap_or_default();
            let p50 = percentile(&attempts, 50);
            let p95 = percentile(&attempts, 95);

            targets.push(TargetStats {
                target_url,
                pending: pending.max(0) as u64,
                delivered_recent: delivered.max(0) as u64,
                expired_recent: expired.max(0) as u64,
                superseded_recent: superseded.max(0) as u64,
                p50_attempts: p50,
                p95_attempts: p95,
                last_success_at: last_success,
                last_failure_at: last_failure,
            });
        }

        // Oldest pending age. Compute now-vs-oldest-row in seconds.
        // Defensive: if the row's timestamp is in the future (clock
        // skew) clamp to 0 rather than report a negative.
        if let Some(ts) = oldest_pending_at {
            if let Ok(t) = chrono::DateTime::parse_from_rfc3339(&ts) {
                let age = (Utc::now() - t.with_timezone(&Utc)).num_seconds();
                queue.oldest_pending_age_seconds = Some(age.max(0));
            }
        }

        Ok(FederationMetricsSnapshot { queue, targets })
    }

    // -- Relay self-identity (#32) -------------------------------------------

    async fn load_relay_identity(
        &self,
    ) -> Result<Option<RelayIdentity>, Box<dyn std::error::Error + Send + Sync>> {
        let row = self
            .conn
            .call(|conn| {
                conn.query_row(
                    "SELECT identity_id, document_json, secrets_json \
                     FROM relay_identity WHERE slot = 'primary'",
                    [],
                    |r| {
                        Ok((
                            r.get::<_, String>(0)?,
                            r.get::<_, String>(1)?,
                            r.get::<_, String>(2)?,
                        ))
                    },
                )
                .optional()
                .map_err(|e| e.into())
            })
            .await?;
        Ok(row.map(|(identity_id, document_json, secrets_json)| RelayIdentity {
            identity_id,
            document_json,
            secrets_json,
        }))
    }

    async fn save_relay_identity(
        &self,
        identity: &RelayIdentity,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // ON CONFLICT UPDATE so the boot path can call this
        // unconditionally; in practice it's only invoked when load
        // returned None, but defensiveness here is cheap.
        let identity_id = identity.identity_id.clone();
        let document_json = identity.document_json.clone();
        let secrets_json = identity.secrets_json.clone();
        let now = Utc::now().to_rfc3339();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "INSERT INTO relay_identity (slot, identity_id, document_json, secrets_json, created_at) \
                     VALUES ('primary', ?1, ?2, ?3, ?4) \
                     ON CONFLICT(slot) DO UPDATE SET \
                        identity_id = excluded.identity_id, \
                        document_json = excluded.document_json, \
                        secrets_json = excluded.secrets_json, \
                        created_at = excluded.created_at",
                    rusqlite::params![identity_id, document_json, secrets_json, now],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }

    async fn save_delivery_receipt(
        &self,
        envelope_id: &str,
        target_url: &str,
        receipt_json: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let envelope_id = envelope_id.to_string();
        let target_url = target_url.to_string();
        let receipt_json = receipt_json.to_string();
        self.conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE outbound_deliveries SET receipt_json = ?1 \
                     WHERE envelope_id = ?2 AND target_url = ?3",
                    rusqlite::params![receipt_json, envelope_id, target_url],
                )
                .map_err(|e| e.into())
            })
            .await?;
        Ok(())
    }
}

/// Return the `p`-th percentile of a sorted-ascending slice of attempt
/// counts using nearest-rank. Returns `0` for empty input — caller can
/// treat that as "no data". Pure function so the storage tests can
/// exercise edge cases without the SQLite roundtrip.
fn percentile(sorted_asc: &[u32], p: u32) -> u32 {
    if sorted_asc.is_empty() {
        return 0;
    }
    let p = p.min(100) as usize;
    // Nearest-rank: index = ceil(p/100 * n) - 1, clamped to [0, n-1].
    let n = sorted_asc.len();
    let idx = ((p * n + 99) / 100).saturating_sub(1).min(n - 1);
    sorted_asc[idx]
}

fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn safe_name(input: &str) -> String {
    input.replace([':', '/'], "_")
}

#[allow(dead_code)]
fn is_expired(envelope: &Envelope) -> bool {
    envelope
        .expires_at
        .as_ref()
        .map(|expires_at| expires_at <= &Utc::now())
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        percentile, ClaimAliasOutcome, FileStore, LifecycleOutcome, ProvisionOutcome, QueueStats,
        RelayIdentity, SqliteStore, Store, StoreOutcome,
    };
    use crate::config::RetentionPolicy;
    use aegis_proto::{
        EncryptedBlob, Envelope, IdentityDocument, IdentityId, PublicKeyRecord, SuiteId,
    };
    use chrono::{Duration, Utc};

    fn sample_envelope(recipient: &str) -> Envelope {
        Envelope::new(
            IdentityId(recipient.to_string()),
            None,
            SuiteId::DemoXChaCha20Poly1305,
            EncryptedBlob {
                nonce_b64: "bm9uY2U=".to_string(),
                ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
                eph_x25519_public_key_b64: None,
                mlkem_ciphertext_b64: None,
            },
        )
    }

    #[tokio::test]
    async fn fetch_skips_and_cleans_up_expired_envelopes() {
        let base = std::env::temp_dir().join(format!("aegis-relay-store-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let mut expired = sample_envelope("amp:did:key:z6MkRecipient");
        expired.expires_at = Some(Utc::now() - Duration::seconds(10));
        let fresh = sample_envelope("amp:did:key:z6MkRecipient");

        store.store(&expired).await.expect("store expired");
        store.store(&fresh).await.expect("store fresh");

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id.0, fresh.envelope_id.0);

        let recipient_dir = base.join("amp_did_key_z6MkRecipient");
        let expired_path = recipient_dir.join(format!("{}.json", expired.envelope_id.0));
        assert!(!tokio::fs::try_exists(expired_path)
            .await
            .expect("exists check"));

        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn acknowledge_marks_envelope_and_fetch_skips_it() {
        let base = std::env::temp_dir().join(format!("aegis-relay-ack-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let envelope = sample_envelope("amp:did:key:z6MkRecipient");
        store.store(&envelope).await.expect("store");
        let outcome = store
            .acknowledge(
                "amp:did:key:z6MkRecipient",
                &envelope.envelope_id.0.to_string(),
            )
            .await
            .expect("ack");
        assert_eq!(outcome, LifecycleOutcome::Acknowledged);

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert!(fetched.is_empty());
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn delete_removes_envelope_file() {
        let base = std::env::temp_dir().join(format!("aegis-relay-del-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let envelope = sample_envelope("amp:did:key:z6MkRecipient");
        let id = envelope.envelope_id.0.to_string();
        store.store(&envelope).await.expect("store");
        let outcome = store
            .delete("amp:did:key:z6MkRecipient", &id)
            .await
            .expect("delete");
        assert_eq!(outcome, LifecycleOutcome::Deleted);

        let fetched = store
            .fetch("amp:did:key:z6MkRecipient")
            .await
            .expect("fetch");
        assert!(fetched.is_empty());
        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    #[tokio::test]
    async fn cleanup_removes_expired_and_orphan_ack_files() {
        let base = std::env::temp_dir().join(format!("aegis-relay-clean-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let mut expired = sample_envelope("amp:did:key:z6MkRecipient");
        expired.expires_at = Some(Utc::now() - Duration::seconds(10));
        store.store(&expired).await.expect("store expired");

        let recipient_dir = base.join("amp_did_key_z6MkRecipient");
        let orphan_ack = recipient_dir.join("orphan-envelope.ack");
        tokio::fs::write(&orphan_ack, b"ack")
            .await
            .expect("write orphan ack");

        let report = store
            .cleanup(&RetentionPolicy {
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            })
            .await
            .expect("cleanup");
        assert_eq!(report.expired_removed, 1);
        assert_eq!(report.orphan_ack_removed, 1);

        let _ = tokio::fs::remove_dir_all(&base).await;
    }

    // -----------------------------------------------------------------------
    // SqliteStore tests
    // -----------------------------------------------------------------------

    fn sample_identity_doc(id: &str) -> IdentityDocument {
        IdentityDocument {
            version: 1,
            identity_id: IdentityId(id.to_string()),
            aliases: vec![],
            signing_keys: vec![PublicKeyRecord {
                key_id: "sig-1".to_string(),
                algorithm: "AMP-ED25519-V1".to_string(),
                public_key_b64: "c2lnbmluZ2tleQ==".to_string(),
            }],
            encryption_keys: vec![],
            supported_suites: vec!["AMP-DEMO-XCHACHA20POLY1305".to_string()],
            relay_endpoints: vec![],
            signature: None,
        }
    }

    #[tokio::test]
    async fn sqlite_store_round_trip_envelope() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let envelope = sample_envelope("amp:did:key:z6MkSqlite");
        store.store(&envelope).await.expect("store");

        let fetched = store.fetch("amp:did:key:z6MkSqlite").await.expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id.0, envelope.envelope_id.0);
    }

    #[tokio::test]
    async fn sqlite_store_acknowledge_hides_from_fetch() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let envelope = sample_envelope("amp:did:key:z6MkSqlite2");
        let id = envelope.envelope_id.0.to_string();
        store.store(&envelope).await.expect("store");

        let outcome = store
            .acknowledge("amp:did:key:z6MkSqlite2", &id)
            .await
            .expect("ack");
        assert_eq!(outcome, LifecycleOutcome::Acknowledged);

        let fetched = store.fetch("amp:did:key:z6MkSqlite2").await.expect("fetch");
        assert!(fetched.is_empty());
    }

    #[tokio::test]
    async fn sqlite_store_delete_removes_envelope() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let envelope = sample_envelope("amp:did:key:z6MkSqlite3");
        let id = envelope.envelope_id.0.to_string();
        store.store(&envelope).await.expect("store");

        let outcome = store
            .delete("amp:did:key:z6MkSqlite3", &id)
            .await
            .expect("delete");
        assert_eq!(outcome, LifecycleOutcome::Deleted);

        let fetched = store.fetch("amp:did:key:z6MkSqlite3").await.expect("fetch");
        assert!(fetched.is_empty());
    }

    #[tokio::test]
    async fn sqlite_store_acknowledge_nonexistent_returns_not_found() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let outcome = store
            .acknowledge("amp:did:key:z6MkMissing", "no-such-id")
            .await
            .expect("ack");
        assert_eq!(outcome, LifecycleOutcome::NotFound);
    }

    #[tokio::test]
    async fn sqlite_store_cleanup_removes_expired() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let mut expired = sample_envelope("amp:did:key:z6MkSqlite4");
        expired.expires_at = Some(Utc::now() - Duration::seconds(10));
        let fresh = sample_envelope("amp:did:key:z6MkSqlite4");
        store.store(&expired).await.expect("store expired");
        store.store(&fresh).await.expect("store fresh");

        let report = store
            .cleanup(&RetentionPolicy {
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            })
            .await
            .expect("cleanup");
        assert_eq!(report.expired_removed, 1);

        let fetched = store.fetch("amp:did:key:z6MkSqlite4").await.expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id.0, fresh.envelope_id.0);
    }

    #[tokio::test]
    async fn sqlite_store_identity_round_trip() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let doc = sample_identity_doc("amp:did:key:z6MkIdentity");
        store.store_identity(&doc).await.expect("store identity");

        let fetched = store
            .fetch_identity("amp:did:key:z6MkIdentity")
            .await
            .expect("fetch identity")
            .expect("should be Some");
        assert_eq!(fetched.identity_id.0, "amp:did:key:z6MkIdentity");
    }

    #[tokio::test]
    async fn sqlite_store_identity_returns_none_for_missing() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let result = store
            .fetch_identity("amp:did:key:z6MkNotStored")
            .await
            .expect("fetch");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn sqlite_store_resolve_alias_returns_matching_identity() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let mut doc = sample_identity_doc("amp:did:key:z6MkIdentityAlias");
        doc.aliases = vec!["alice@mesh".to_string()];
        store.store_identity(&doc).await.expect("store identity");

        let resolved = store
            .resolve_alias("alice@mesh")
            .await
            .expect("resolve alias");
        assert!(resolved.is_some());
        assert_eq!(
            resolved.unwrap().identity_id.0,
            "amp:did:key:z6MkIdentityAlias"
        );
    }

    #[tokio::test]
    async fn sqlite_store_resolve_alias_returns_none_for_unknown() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let result = store
            .resolve_alias("nobody@nowhere")
            .await
            .expect("resolve");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn sqlite_store_alias_index_updated_on_re_publish() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let id = "amp:did:key:z6MkAliasUpdate";

        // First publish: alias "old@mesh"
        let mut doc = sample_identity_doc(id);
        doc.aliases = vec!["old@mesh".to_string()];
        store.store_identity(&doc).await.expect("store v1");

        // Re-publish: alias changed to "new@mesh"
        doc.aliases = vec!["new@mesh".to_string()];
        store.store_identity(&doc).await.expect("store v2");

        // Old alias must not resolve any more
        let old = store.resolve_alias("old@mesh").await.expect("resolve old");
        assert!(
            old.is_none(),
            "stale alias must not resolve after re-publish"
        );

        // New alias must resolve
        let new = store.resolve_alias("new@mesh").await.expect("resolve new");
        assert!(new.is_some());
        assert_eq!(new.unwrap().identity_id.0, id);
    }

    #[tokio::test]
    async fn sqlite_store_multiple_aliases_all_resolve() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let id = "amp:did:key:z6MkMultiAlias";
        let mut doc = sample_identity_doc(id);
        doc.aliases = vec!["alice@mesh".to_string(), "alice@example.com".to_string()];
        store.store_identity(&doc).await.expect("store");

        for alias in &["alice@mesh", "alice@example.com"] {
            let resolved = store.resolve_alias(alias).await.expect("resolve");
            assert!(resolved.is_some(), "alias {alias} must resolve");
            assert_eq!(resolved.unwrap().identity_id.0, id);
        }
    }

    #[tokio::test]
    async fn sqlite_store_fetch_skips_expired() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let mut expired = sample_envelope("amp:did:key:z6MkExpiry");
        expired.expires_at = Some(Utc::now() - Duration::seconds(5));
        store.store(&expired).await.expect("store");

        let fetched = store.fetch("amp:did:key:z6MkExpiry").await.expect("fetch");
        assert!(
            fetched.is_empty(),
            "expired envelope should not be returned"
        );
    }

    // -----------------------------------------------------------------------
    // Prekey consumption tests (RFC-0003 §12)
    // -----------------------------------------------------------------------

    /// Publish a one-time prekey for `recipient` so that subsequent
    /// `store_with_prekey_consumption` calls referencing `key_id` pass the
    /// published-check. Used by phase-1 enforcement tests.
    async fn publish_test_prekey(store: &SqliteStore, recipient: &str, key_id: &str) {
        use aegis_proto::{IdentityId, PrekeyBundle, PublicKeyRecord};
        let bundle = PrekeyBundle {
            identity_id: IdentityId(recipient.to_string()),
            signed_prekeys: vec![],
            one_time_prekeys: vec![PublicKeyRecord {
                key_id: key_id.to_string(),
                algorithm: "AMP-MLKEM768-V1".to_string(),
                public_key_b64: "AAAA".to_string(),
            }],
            supported_suites: vec![],
            expires_at: None,
            signature: Some("test-signature".to_string()),
        };
        store
            .store_one_time_prekeys(&bundle)
            .await
            .expect("publish test prekey");
    }

    #[tokio::test]
    async fn prekey_consumption_empty_list_is_no_op() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let envelope = sample_envelope("amp:did:key:z6MkPkEmpty");
        assert!(envelope.used_prekey_ids.is_empty());

        let outcome = store
            .store_with_prekey_consumption(&envelope)
            .await
            .expect("store");
        assert_eq!(outcome, StoreOutcome::Stored);

        let fetched = store.fetch("amp:did:key:z6MkPkEmpty").await.expect("fetch");
        assert_eq!(fetched.len(), 1);
    }

    #[tokio::test]
    async fn prekey_consumption_first_use_succeeds() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let recipient = "amp:did:key:z6MkPkFirst";
        publish_test_prekey(&store, recipient, "pk-1").await;

        let mut envelope = sample_envelope(recipient);
        envelope.used_prekey_ids = vec!["pk-1".to_string()];

        let outcome = store
            .store_with_prekey_consumption(&envelope)
            .await
            .expect("store");
        assert_eq!(outcome, StoreOutcome::Stored);
    }

    #[tokio::test]
    async fn prekey_consumption_unknown_prekey_rejected() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let mut envelope = sample_envelope("amp:did:key:z6MkPkUnknown");
        envelope.used_prekey_ids = vec!["pk-never-published".to_string()];

        let outcome = store
            .store_with_prekey_consumption(&envelope)
            .await
            .expect("store");
        assert_eq!(
            outcome,
            StoreOutcome::UnknownPrekey {
                key_id: "pk-never-published".to_string()
            }
        );

        let fetched = store
            .fetch("amp:did:key:z6MkPkUnknown")
            .await
            .expect("fetch");
        assert!(fetched.is_empty(), "envelope must not be persisted");
    }

    #[tokio::test]
    async fn prekey_consumption_replay_rejected() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let recipient = "amp:did:key:z6MkPkReplay";
        publish_test_prekey(&store, recipient, "pk-replay").await;

        let mut first = sample_envelope(recipient);
        first.used_prekey_ids = vec!["pk-replay".to_string()];
        let outcome1 = store
            .store_with_prekey_consumption(&first)
            .await
            .expect("first store");
        assert_eq!(outcome1, StoreOutcome::Stored);

        let mut second = sample_envelope(recipient);
        second.used_prekey_ids = vec!["pk-replay".to_string()];
        let outcome2 = store
            .store_with_prekey_consumption(&second)
            .await
            .expect("second store");
        assert_eq!(
            outcome2,
            StoreOutcome::PrekeyAlreadyUsed {
                key_id: "pk-replay".to_string()
            }
        );

        // Only the first envelope should be persisted.
        let fetched = store.fetch(recipient).await.expect("fetch");
        assert_eq!(fetched.len(), 1);
        assert_eq!(fetched[0].envelope_id.0, first.envelope_id.0);
    }

    #[tokio::test]
    async fn prekey_consumption_all_or_nothing_rollback() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let recipient = "amp:did:key:z6MkPkRollback";
        publish_test_prekey(&store, recipient, "pk-already").await;
        publish_test_prekey(&store, recipient, "pk-fresh").await;

        // Pre-consume one key.
        let mut prior = sample_envelope(recipient);
        prior.used_prekey_ids = vec!["pk-already".to_string()];
        store
            .store_with_prekey_consumption(&prior)
            .await
            .expect("prior");

        // Attempt second envelope claiming a fresh key + the already-consumed one.
        let mut second = sample_envelope(recipient);
        second.used_prekey_ids = vec!["pk-fresh".to_string(), "pk-already".to_string()];
        let outcome = store
            .store_with_prekey_consumption(&second)
            .await
            .expect("second");
        assert_eq!(
            outcome,
            StoreOutcome::PrekeyAlreadyUsed {
                key_id: "pk-already".to_string()
            }
        );

        // Second envelope must NOT be persisted.
        let fetched = store.fetch(recipient).await.expect("fetch");
        assert_eq!(
            fetched.len(),
            1,
            "rollback should leave only the first envelope"
        );
        assert_eq!(fetched[0].envelope_id.0, prior.envelope_id.0);

        // Critically: the fresh key MUST NOT be marked consumed (rollback).
        // Verify by attempting to use it on a new envelope; should succeed.
        let mut third = sample_envelope(recipient);
        third.used_prekey_ids = vec!["pk-fresh".to_string()];
        let outcome3 = store
            .store_with_prekey_consumption(&third)
            .await
            .expect("third");
        assert_eq!(
            outcome3,
            StoreOutcome::Stored,
            "pk-fresh should not have been consumed by the rolled-back transaction"
        );
    }

    #[tokio::test]
    async fn prekey_consumption_isolated_per_recipient() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        publish_test_prekey(&store, "amp:did:key:z6MkRcptA", "pk-shared").await;
        publish_test_prekey(&store, "amp:did:key:z6MkRcptB", "pk-shared").await;

        // Same key_id, different recipients — both must be allowed.
        let mut a = sample_envelope("amp:did:key:z6MkRcptA");
        a.used_prekey_ids = vec!["pk-shared".to_string()];
        assert_eq!(
            store.store_with_prekey_consumption(&a).await.expect("a"),
            StoreOutcome::Stored
        );

        let mut b = sample_envelope("amp:did:key:z6MkRcptB");
        b.used_prekey_ids = vec!["pk-shared".to_string()];
        assert_eq!(
            store.store_with_prekey_consumption(&b).await.expect("b"),
            StoreOutcome::Stored
        );
    }

    // -----------------------------------------------------------------------
    // Prekey publish / claim tests (RFC-0004 §5/§12, v0.3 phase 2)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn store_one_time_prekeys_inserts_and_skips_duplicates() {
        use aegis_proto::{IdentityId, PrekeyBundle, PublicKeyRecord};
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let id = "amp:did:key:z6MkPubPk";

        let bundle = PrekeyBundle {
            identity_id: IdentityId(id.to_string()),
            signed_prekeys: vec![],
            one_time_prekeys: vec![
                PublicKeyRecord {
                    key_id: "ot-1".to_string(),
                    algorithm: "AMP-MLKEM768-V1".to_string(),
                    public_key_b64: "AAAA".to_string(),
                },
                PublicKeyRecord {
                    key_id: "ot-2".to_string(),
                    algorithm: "AMP-MLKEM768-V1".to_string(),
                    public_key_b64: "BBBB".to_string(),
                },
            ],
            supported_suites: vec![],
            expires_at: None,
            signature: Some("sig".to_string()),
        };
        let report = store
            .store_one_time_prekeys(&bundle)
            .await
            .expect("publish");
        assert_eq!(report.inserted, 2);
        assert_eq!(report.skipped, 0);

        // Republish the same bundle — both rows should be skipped (idempotent).
        let report2 = store
            .store_one_time_prekeys(&bundle)
            .await
            .expect("republish");
        assert_eq!(report2.inserted, 0);
        assert_eq!(report2.skipped, 2);
    }

    #[tokio::test]
    async fn claim_one_time_prekey_returns_one_then_pool_empties() {
        use aegis_proto::{IdentityId, PrekeyBundle, PublicKeyRecord};
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let id = "amp:did:key:z6MkClaimPk";

        let bundle = PrekeyBundle {
            identity_id: IdentityId(id.to_string()),
            signed_prekeys: vec![],
            one_time_prekeys: vec![PublicKeyRecord {
                key_id: "ot-only".to_string(),
                algorithm: "AMP-MLKEM768-V1".to_string(),
                public_key_b64: "Z29uZQ==".to_string(),
            }],
            supported_suites: vec![],
            expires_at: None,
            signature: Some("sig".to_string()),
        };
        store
            .store_one_time_prekeys(&bundle)
            .await
            .expect("publish");

        let first = store
            .claim_one_time_prekey(id)
            .await
            .expect("claim 1")
            .expect("should return one prekey");
        assert_eq!(first.key_id, "ot-only");
        assert_eq!(first.algorithm, "AMP-MLKEM768-V1");
        assert_eq!(first.public_key_b64, "Z29uZQ==");

        // Pool is now empty.
        let second = store.claim_one_time_prekey(id).await.expect("claim 2");
        assert!(second.is_none(), "pool should be empty after one claim");
    }

    #[tokio::test]
    async fn claim_one_time_prekey_concurrent_serialization() {
        // Two parallel claims on the same identity should each return a
        // distinct prekey when the pool has two entries — never the same one.
        use aegis_proto::{IdentityId, PrekeyBundle, PublicKeyRecord};
        let store = std::sync::Arc::new(
            SqliteStore::open_in_memory()
                .await
                .expect("in-memory sqlite"),
        );
        let id = "amp:did:key:z6MkConcurrent";

        let bundle = PrekeyBundle {
            identity_id: IdentityId(id.to_string()),
            signed_prekeys: vec![],
            one_time_prekeys: vec![
                PublicKeyRecord {
                    key_id: "ot-a".to_string(),
                    algorithm: "AMP-MLKEM768-V1".to_string(),
                    public_key_b64: "QQ==".to_string(),
                },
                PublicKeyRecord {
                    key_id: "ot-b".to_string(),
                    algorithm: "AMP-MLKEM768-V1".to_string(),
                    public_key_b64: "Qg==".to_string(),
                },
            ],
            supported_suites: vec![],
            expires_at: None,
            signature: Some("sig".to_string()),
        };
        store
            .store_one_time_prekeys(&bundle)
            .await
            .expect("publish");

        let s1 = std::sync::Arc::clone(&store);
        let s2 = std::sync::Arc::clone(&store);
        let id_a = id.to_string();
        let id_b = id.to_string();
        let (r1, r2) = tokio::join!(
            tokio::spawn(async move { s1.claim_one_time_prekey(&id_a).await }),
            tokio::spawn(async move { s2.claim_one_time_prekey(&id_b).await }),
        );

        let claimed_1 = r1.expect("join 1").expect("claim 1").expect("got prekey 1");
        let claimed_2 = r2.expect("join 2").expect("claim 2").expect("got prekey 2");
        assert_ne!(
            claimed_1.key_id, claimed_2.key_id,
            "concurrent claims must return distinct prekeys"
        );

        // Pool now exhausted.
        let third = store.claim_one_time_prekey(id).await.expect("claim 3");
        assert!(third.is_none());
    }

    #[tokio::test]
    async fn claim_one_time_prekey_returns_none_for_unknown_identity() {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("in-memory sqlite");
        let claimed = store
            .claim_one_time_prekey("amp:did:key:z6MkNoSuchPk")
            .await
            .expect("claim");
        assert!(claimed.is_none());
    }

    #[tokio::test]
    async fn served_domain_lifecycle() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");

        assert!(!store.has_served_domains().await.unwrap());

        let entry = store
            .add_served_domain("Example.COM", "tok-abc")
            .await
            .expect("add");
        assert_eq!(entry.domain, "Example.COM");
        assert!(entry.verified_at.is_none());

        // Idempotent re-add returns existing entry, doesn't reset token.
        let again = store
            .add_served_domain("Example.COM", "different-token")
            .await
            .expect("add again");
        assert_eq!(again.verification_token, "tok-abc");

        // has_served_domains is verified-only.
        assert!(!store.has_served_domains().await.unwrap());

        let ok = store.mark_domain_verified("Example.COM").await.unwrap();
        assert!(ok);
        assert!(store.has_served_domains().await.unwrap());

        let fetched = store
            .get_served_domain("Example.COM")
            .await
            .unwrap()
            .expect("present");
        assert!(fetched.verified_at.is_some());

        let removed = store.release_served_domain("Example.COM").await.unwrap();
        assert_eq!(removed, 0);
        assert!(store.get_served_domain("Example.COM").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn provision_user_requires_verified_domain() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");

        let outcome = store.provision_user("alice@example.com").await.unwrap();
        assert_eq!(outcome, ProvisionOutcome::DomainNotServed);

        store
            .add_served_domain("example.com", "tok-1")
            .await
            .unwrap();
        // Domain claimed but not yet verified — still rejected.
        let outcome = store.provision_user("alice@example.com").await.unwrap();
        assert_eq!(outcome, ProvisionOutcome::DomainNotServed);

        store.mark_domain_verified("example.com").await.unwrap();
        let outcome = store.provision_user("alice@example.com").await.unwrap();
        assert_eq!(outcome, ProvisionOutcome::Created);

        let outcome = store.provision_user("alice@example.com").await.unwrap();
        assert_eq!(outcome, ProvisionOutcome::AlreadyExists);
    }

    #[tokio::test]
    async fn claim_provisioned_alias_blocks_hijack() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .add_served_domain("example.com", "tok-1")
            .await
            .unwrap();
        store.mark_domain_verified("example.com").await.unwrap();
        store.provision_user("bob@example.com").await.unwrap();

        let bound = store
            .claim_provisioned_alias("bob@example.com", "amp:did:key:zBob")
            .await
            .unwrap();
        assert_eq!(bound, ClaimAliasOutcome::Bound);

        // Same identity rebinding is fine.
        let bound_again = store
            .claim_provisioned_alias("bob@example.com", "amp:did:key:zBob")
            .await
            .unwrap();
        assert_eq!(bound_again, ClaimAliasOutcome::Bound);

        // Different identity is rejected.
        let other = store
            .claim_provisioned_alias("bob@example.com", "amp:did:key:zEve")
            .await
            .unwrap();
        assert!(matches!(other, ClaimAliasOutcome::OwnedByOther { .. }));

        // Unprovisioned alias is allowed (open binding).
        let np = store
            .claim_provisioned_alias("nobody@example.com", "amp:did:key:zEve")
            .await
            .unwrap();
        assert_eq!(np, ClaimAliasOutcome::NotProvisioned);
    }

    #[tokio::test]
    async fn release_domain_purges_aliases_and_provisions() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .add_served_domain("example.com", "tok-1")
            .await
            .unwrap();
        store.mark_domain_verified("example.com").await.unwrap();
        store.provision_user("alice@example.com").await.unwrap();

        // Insert a fake alias row directly to simulate an active identity.
        store
            .conn
            .call(|conn| {
                conn.execute(
                    "INSERT INTO identity_aliases (alias, identity_id) VALUES (?1, ?2)",
                    rusqlite::params!["alice@example.com", "amp:did:key:zAlice"],
                )
                .map_err(|e| e.into())
            })
            .await
            .unwrap();

        let removed = store.release_served_domain("example.com").await.unwrap();
        assert_eq!(removed, 1);

        let users = store
            .list_provisioned_users(Some("example.com"), 0, 10)
            .await
            .unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn deprovision_user_purges_envelopes_for_bound_identity() {
        // Captures aegis-relay#24 — DELETE /admin/users/:alias should drop
        // the alias entry AND every envelope addressed to the bound
        // identity. Envelopes are keyed by `recipient_id` (identity_id),
        // so the bridge from "deprovision user@domain" → "drain inbox"
        // is the alias row.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .add_served_domain("example.com", "tok-1")
            .await
            .unwrap();
        store.mark_domain_verified("example.com").await.unwrap();
        store.provision_user("alice@example.com").await.unwrap();

        let identity_id = "amp:did:key:zAliceDeprovisionTest";
        let bound = store
            .claim_provisioned_alias("alice@example.com", identity_id)
            .await
            .unwrap();
        assert_eq!(bound, ClaimAliasOutcome::Bound);

        // Insert two envelopes for this identity and one for an unrelated
        // identity — the unrelated envelope must NOT be purged.
        for _ in 0..2 {
            store.store(&sample_envelope(identity_id)).await.unwrap();
        }
        let other_identity = "amp:did:key:zBobUntouched";
        store
            .store(&sample_envelope(other_identity))
            .await
            .unwrap();

        let outcome = store.deprovision_user("alice@example.com").await.unwrap();
        assert!(outcome.alias_removed);
        assert_eq!(outcome.envelopes_purged, 2);

        // Bob's envelope is still there; Alice's queue is empty.
        let alice_remaining = store.fetch(identity_id).await.unwrap();
        assert!(alice_remaining.is_empty());
        let bob_remaining = store
            .fetch(other_identity)
            .await
            .unwrap();
        assert_eq!(bob_remaining.len(), 1);

        // The provisioned-user roster row is gone too.
        let users = store
            .list_provisioned_users(Some("example.com"), 0, 10)
            .await
            .unwrap();
        assert!(users.is_empty());
    }

    #[tokio::test]
    async fn deprovision_user_without_bound_identity_purges_zero() {
        // When an alias is provisioned but never claimed by an identity,
        // there's nothing in the queue addressed to it — `envelopes_purged`
        // must be exactly 0 (no false-positive wildcard purge).
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .add_served_domain("example.com", "tok-2")
            .await
            .unwrap();
        store.mark_domain_verified("example.com").await.unwrap();
        store.provision_user("ghost@example.com").await.unwrap();

        // An envelope addressed to a totally unrelated identity should
        // not be touched.
        let other = "amp:did:key:zSomeoneElse";
        store.store(&sample_envelope(other)).await.unwrap();

        let outcome = store.deprovision_user("ghost@example.com").await.unwrap();
        assert!(outcome.alias_removed);
        assert_eq!(outcome.envelopes_purged, 0);

        let other_remaining = store.fetch(other).await.unwrap();
        assert_eq!(other_remaining.len(), 1);
    }

    #[tokio::test]
    async fn deprovision_user_returns_false_when_alias_not_provisioned() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let outcome = store.deprovision_user("nobody@example.com").await.unwrap();
        assert!(!outcome.alias_removed);
        assert_eq!(outcome.envelopes_purged, 0);
    }

    #[tokio::test]
    async fn list_served_domains_paginates_consistently() {
        // Pagination on `GET /admin/domains` is the second half of the
        // change in #24's PR — make sure the slice + count are
        // consistent across pages.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        for i in 0..5 {
            store
                .add_served_domain(&format!("d{}.example.com", i), &format!("tok-{}", i))
                .await
                .unwrap();
        }

        let total = store.count_served_domains().await.unwrap();
        assert_eq!(total, 5);

        let page1 = store.list_served_domains(0, 2).await.unwrap();
        assert_eq!(page1.len(), 2);
        let page2 = store.list_served_domains(2, 2).await.unwrap();
        assert_eq!(page2.len(), 2);
        let page3 = store.list_served_domains(4, 2).await.unwrap();
        assert_eq!(page3.len(), 1);

        // Pages are ordered by added_at ASC; combined they should equal
        // the 5 domains we inserted, in insertion order.
        let combined: Vec<_> = page1
            .iter()
            .chain(page2.iter())
            .chain(page3.iter())
            .map(|e| e.domain.clone())
            .collect();
        assert_eq!(
            combined,
            vec![
                "d0.example.com",
                "d1.example.com",
                "d2.example.com",
                "d3.example.com",
                "d4.example.com",
            ]
        );

        // Out-of-range offsets yield empty pages, not errors.
        let page_oob = store.list_served_domains(99, 10).await.unwrap();
        assert!(page_oob.is_empty());
    }

    // Federation queue (#28) ---------------------------------------------

    #[tokio::test]
    async fn outbound_delivery_round_trip() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        // Stash a real envelope so mark_delivery_delivered can drop it.
        let env = sample_envelope("amp:did:key:zRecipient");
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        // First enqueue is a real INSERT.
        store
            .enqueue_outbound_delivery(&envelope_id, "https://peer.example/v1/envelopes")
            .await
            .unwrap();

        // Idempotent: double-enqueueing the same (envelope, target) is a
        // no-op so retried POSTs from the originating sender don't double
        // up the queue.
        store
            .enqueue_outbound_delivery(&envelope_id, "https://peer.example/v1/envelopes")
            .await
            .unwrap();

        let due = store.next_pending_delivery().await.unwrap().unwrap();
        assert_eq!(due.envelope_id, envelope_id);
        assert_eq!(due.target_url, "https://peer.example/v1/envelopes");
        assert_eq!(due.status, "pending");
        assert_eq!(due.attempts, 0);

        // Mark delivered: status → 'delivered' AND envelope is purged.
        // Single-target case: there are no siblings to supersede.
        let superseded = store
            .mark_delivery_delivered(&envelope_id, "https://peer.example/v1/envelopes")
            .await
            .unwrap();
        assert!(
            superseded.is_empty(),
            "single-target delivery should report no superseded siblings, got {:?}",
            superseded
        );

        // No longer pending.
        let after = store.next_pending_delivery().await.unwrap();
        assert!(after.is_none());

        // Envelope itself is gone from the local queue.
        let json = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(json.is_none(), "delivered envelope should be expired locally");
    }

    #[tokio::test]
    async fn outbound_delivery_attempt_advances_backoff() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let envelope_id = "env-retry";
        store
            .enqueue_outbound_delivery(envelope_id, "https://peer.example")
            .await
            .unwrap();

        let due = store.next_pending_delivery().await.unwrap().unwrap();
        assert_eq!(due.attempts, 0);

        // Push next_retry_at into the future and bump attempt count.
        let future = Utc::now() + chrono::Duration::minutes(5);
        store
            .mark_delivery_attempt(envelope_id, "https://peer.example", "boom", future)
            .await
            .unwrap();

        // Now the row is no longer "due" so next_pending_delivery skips it.
        let after = store.next_pending_delivery().await.unwrap();
        assert!(
            after.is_none(),
            "row backed off to the future shouldn't be returned, got {:?}",
            after
        );
    }

    #[tokio::test]
    async fn outbound_delivery_expired_is_skipped() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .enqueue_outbound_delivery("env-x", "https://peer.example")
            .await
            .unwrap();
        store
            .mark_delivery_expired("env-x", "https://peer.example")
            .await
            .unwrap();

        let next = store.next_pending_delivery().await.unwrap();
        assert!(next.is_none());
    }

    #[tokio::test]
    async fn fetch_envelope_json_returns_stored_bytes() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let env = sample_envelope("amp:did:key:zJsonReader");
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let json = store
            .fetch_envelope_json(&envelope_id)
            .await
            .unwrap()
            .expect("envelope_json should be present");
        // Round-trips through serde, so it's well-formed JSON pointing at
        // the right recipient. We don't assert byte-equality with serde's
        // input (that's an internal detail of the storage layer).
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            parsed["recipient_id"].as_str().unwrap(),
            "amp:did:key:zJsonReader"
        );

        // Unknown id → None
        let missing = store.fetch_envelope_json("env-does-not-exist").await.unwrap();
        assert!(missing.is_none());
    }

    // --- Federation metrics (mlaify/aegis-relay#31) ----------------------

    #[test]
    fn percentile_handles_edge_cases() {
        // Empty input → 0 (caller treats as "no data")
        assert_eq!(percentile(&[], 50), 0);
        // Single element: p* always returns it
        assert_eq!(percentile(&[3], 0), 3);
        assert_eq!(percentile(&[3], 50), 3);
        assert_eq!(percentile(&[3], 95), 3);
        // Standard nearest-rank semantics on a tidy list. n=7;
        // p=50 → ceil(0.5 * 7) - 1 = 3 → sorted[3] = 2.
        // p=95 → ceil(0.95 * 7) - 1 = 6 → sorted[6] = 7.
        let sorted = [1, 1, 1, 2, 3, 5, 7];
        assert_eq!(percentile(&sorted, 50), 2);
        assert_eq!(percentile(&sorted, 95), 7);
        // p > 100 clamps to 100 (which still yields the last element).
        assert_eq!(percentile(&sorted, 200), 7);
    }

    #[tokio::test]
    async fn federation_metrics_empty_queue_returns_zeros() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let snap = store.federation_metrics(86_400).await.unwrap();
        assert_eq!(snap.queue, QueueStats::default());
        assert!(snap.targets.is_empty());
        assert!(snap.queue.oldest_pending_age_seconds.is_none());
    }

    #[tokio::test]
    async fn federation_metrics_aggregates_per_target() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        // Stash a real envelope so mark_delivery_delivered's
        // envelope-purge step doesn't fail noisily.
        let env = sample_envelope("amp:did:key:zMetricsRecipient");
        let env_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        // Three targets, varied outcomes — designed to exercise every
        // branch the SQL aggregator has:
        //   peer-fast: delivered first try
        //   peer-slow: delivered after 3 attempts (so p50 ≠ p95)
        //   peer-down: 5xx-flavored — push expired
        for target in ["https://peer-fast", "https://peer-slow", "https://peer-down"] {
            store.enqueue_outbound_delivery(&env_id, target).await.unwrap();
        }

        // peer-slow took 3 attempts. Bump its attempts column to match
        // (the trait's mark_delivery_attempt does this in production).
        store
            .conn
            .call({
                let env_id = env_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE outbound_deliveries SET attempts = 3 \
                         WHERE envelope_id = ?1 AND target_url = ?2",
                        rusqlite::params![env_id, "https://peer-slow"],
                    )
                    .map_err(|e| e.into())
                }
            })
            .await
            .unwrap();

        // peer-fast wins → flips peer-slow + peer-down to 'superseded'
        // by the supersede transaction. We don't want that for this
        // test (we want delivered + expired in different rows for
        // assertion variety), so bypass that path: directly mark
        // peer-fast delivered FIRST without going through siblings,
        // by using the public `mark_delivery_delivered` and accepting
        // the supersede side-effect ... wait, let's instead drive
        // each target into its terminal state with bypassing siblings.
        //
        // Approach: mark peer-down expired first, peer-slow delivered
        // (its solo-target, no siblings to supersede), peer-fast
        // delivered (also solo) — but they share envelope_id so
        // that's not actually solo. Easiest: use FRESH envelope_ids
        // per target.
        store
            .mark_delivery_expired(&env_id, "https://peer-down")
            .await
            .unwrap();

        // Multiple delivered envelopes for peer-fast (drives delivered
        // count up + p50/p95 stays at 1).
        for i in 0..4 {
            let mut env_i = sample_envelope("amp:did:key:zMetricsRecipient");
            // Force a unique envelope_id per iteration (Envelope::new
            // already does this via UUID so we just need to call it
            // again — `sample_envelope` returns a fresh UUID).
            env_i.envelope_id = aegis_proto::EnvelopeId(uuid::Uuid::new_v4());
            let id = env_i.envelope_id.0.to_string();
            store.store(&env_i).await.unwrap();
            store
                .enqueue_outbound_delivery(&id, "https://peer-fast")
                .await
                .unwrap();
            store
                .mark_delivery_delivered(&id, "https://peer-fast")
                .await
                .unwrap();
            // peer-fast's `attempts` stays at 0 in storage; we want a
            // realistic 1 to model "delivered first try".
            store
                .conn
                .call({
                    let id = id.clone();
                    move |conn| {
                        conn.execute(
                            "UPDATE outbound_deliveries SET attempts = 1 \
                             WHERE envelope_id = ?1 AND target_url = ?2",
                            rusqlite::params![id, "https://peer-fast"],
                        )
                        .map_err(|e| e.into())
                    }
                })
                .await
                .unwrap();
            // Drop the iteration counter from rustfmt's notice.
            let _ = i;
        }

        // peer-slow: deliver one envelope after 3 attempts.
        let mut slow_env = sample_envelope("amp:did:key:zMetricsRecipient");
        slow_env.envelope_id = aegis_proto::EnvelopeId(uuid::Uuid::new_v4());
        let slow_id = slow_env.envelope_id.0.to_string();
        store.store(&slow_env).await.unwrap();
        store
            .enqueue_outbound_delivery(&slow_id, "https://peer-slow-2")
            .await
            .unwrap();
        store
            .mark_delivery_delivered(&slow_id, "https://peer-slow-2")
            .await
            .unwrap();
        store
            .conn
            .call({
                let id = slow_id.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE outbound_deliveries SET attempts = 4 \
                         WHERE envelope_id = ?1 AND target_url = ?2",
                        rusqlite::params![id, "https://peer-slow-2"],
                    )
                    .map_err(|e| e.into())
                }
            })
            .await
            .unwrap();

        // Window covering everything we just inserted.
        let snap = store.federation_metrics(86_400).await.unwrap();

        // Targets are returned alphabetically (ORDER BY target_url).
        let target_urls: Vec<&str> = snap.targets.iter().map(|t| t.target_url.as_str()).collect();
        assert!(
            target_urls.contains(&"https://peer-down"),
            "expected peer-down in {:?}",
            target_urls
        );
        assert!(target_urls.contains(&"https://peer-fast"));
        assert!(target_urls.contains(&"https://peer-slow-2"));

        let fast = snap.targets.iter().find(|t| t.target_url == "https://peer-fast").unwrap();
        assert_eq!(fast.delivered_recent, 4);
        assert_eq!(fast.expired_recent, 0);
        assert_eq!(fast.p50_attempts, 1);
        assert_eq!(fast.p95_attempts, 1);
        assert!(fast.last_success_at.is_some());

        let slow = snap.targets.iter().find(|t| t.target_url == "https://peer-slow-2").unwrap();
        assert_eq!(slow.delivered_recent, 1);
        assert_eq!(slow.p50_attempts, 4);

        let down = snap.targets.iter().find(|t| t.target_url == "https://peer-down").unwrap();
        assert_eq!(down.expired_recent, 1);
        assert_eq!(down.delivered_recent, 0);
        assert!(down.last_failure_at.is_some());

        // Queue rollup sums over all three targets.
        assert_eq!(snap.queue.delivered_recent, 5);
        assert_eq!(snap.queue.expired_recent, 1);
    }

    #[tokio::test]
    async fn federation_metrics_window_excludes_old_rows() {
        // A row delivered well before the window cutoff must NOT count
        // toward `delivered_recent`. We simulate "old" by stamping a
        // delivered_at in the past directly via SQL.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let env = sample_envelope("amp:did:key:zWindowRecipient");
        let env_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();
        store
            .enqueue_outbound_delivery(&env_id, "https://stale.example")
            .await
            .unwrap();
        store
            .mark_delivery_delivered(&env_id, "https://stale.example")
            .await
            .unwrap();

        // Backdate this row's delivered_at + last_attempt_at by 7 days
        // so a 24h window ignores it.
        let week_ago = (Utc::now() - chrono::Duration::days(7)).to_rfc3339();
        store
            .conn
            .call({
                let env_id = env_id.clone();
                let stamp = week_ago.clone();
                move |conn| {
                    conn.execute(
                        "UPDATE outbound_deliveries SET delivered_at = ?1, last_attempt_at = ?1 \
                         WHERE envelope_id = ?2",
                        rusqlite::params![stamp, env_id],
                    )
                    .map_err(|e| e.into())
                }
            })
            .await
            .unwrap();

        let day = store.federation_metrics(86_400).await.unwrap();
        let stale = day.targets.iter().find(|t| t.target_url == "https://stale.example");
        // Either the target row is absent (no in-window activity at all
        // and aggregator returns the row but with all zeros) or its
        // delivered_recent is 0. Either way must NOT be counted.
        match stale {
            None => {
                // Acceptable — could happen if status filter excluded it.
            }
            Some(t) => {
                assert_eq!(t.delivered_recent, 0);
            }
        }

        // Widening the window to 30d picks it up again.
        let month = store.federation_metrics(30 * 86_400).await.unwrap();
        let stale_30d = month
            .targets
            .iter()
            .find(|t| t.target_url == "https://stale.example")
            .expect("target row appears in widened window");
        assert_eq!(stale_30d.delivered_recent, 1);
    }

    #[tokio::test]
    async fn federation_metrics_oldest_pending_age_reports_seconds() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        // Empty queue → no oldest age reported.
        let empty = store.federation_metrics(86_400).await.unwrap();
        assert!(empty.queue.oldest_pending_age_seconds.is_none());

        // Enqueue a row, backdate created_at by 5 minutes.
        store
            .enqueue_outbound_delivery("env-old", "https://peer.example")
            .await
            .unwrap();
        let five_min_ago = (Utc::now() - chrono::Duration::minutes(5)).to_rfc3339();
        store
            .conn
            .call(move |conn| {
                conn.execute(
                    "UPDATE outbound_deliveries SET created_at = ?1 WHERE envelope_id = 'env-old'",
                    rusqlite::params![five_min_ago],
                )
                .map_err(|e| e.into())
            })
            .await
            .unwrap();

        let snap = store.federation_metrics(86_400).await.unwrap();
        let age = snap.queue.oldest_pending_age_seconds.expect("age present");
        assert!(
            age >= 5 * 60 - 5 && age <= 5 * 60 + 5,
            "expected ~300s, got {age}"
        );
        assert_eq!(snap.queue.pending, 1);
    }

    // --- Relay self-identity (mlaify/aegis-relay#32) ----------------------

    #[tokio::test]
    async fn relay_identity_round_trip() {
        // Save → load → equality. SqliteStore is the only persistent
        // backend; FileStore is a dev scaffold that returns None.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");

        // Empty store starts with no identity.
        assert!(store.load_relay_identity().await.unwrap().is_none());

        let identity = RelayIdentity {
            identity_id: "amp:did:key:zRelayTest".to_string(),
            document_json: r#"{"version":1,"identity_id":"amp:did:key:zRelayTest"}"#
                .to_string(),
            secrets_json: r#"{"identity_id":"amp:did:key:zRelayTest","algorithm":"AMP-HYBRID-PQ-PRIVATE-V1","x25519_private_key_b64":"","kyber768_secret_key_b64":"","ed25519_signing_seed_b64":"","dilithium3_secret_key_b64":""}"#
                .to_string(),
        };
        store.save_relay_identity(&identity).await.unwrap();

        let loaded = store.load_relay_identity().await.unwrap().expect("loaded");
        assert_eq!(loaded.identity_id, identity.identity_id);
        assert_eq!(loaded.document_json, identity.document_json);
        assert_eq!(loaded.secrets_json, identity.secrets_json);
    }

    #[tokio::test]
    async fn relay_identity_save_overwrites_existing_slot() {
        // The boot path only saves when load returned None, but the
        // storage layer accepts repeated saves (UPSERT). Belt-and-
        // suspenders: confirm rotation would Just Work if we ever
        // wire it.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        for ident_id in ["amp:did:key:zRelayA", "amp:did:key:zRelayB"] {
            let identity = RelayIdentity {
                identity_id: ident_id.to_string(),
                document_json: format!(r#"{{"identity_id":"{ident_id}"}}"#),
                secrets_json: format!(r#"{{"identity_id":"{ident_id}"}}"#),
            };
            store.save_relay_identity(&identity).await.unwrap();
        }
        let loaded = store.load_relay_identity().await.unwrap().expect("loaded");
        assert_eq!(loaded.identity_id, "amp:did:key:zRelayB");
    }

    #[tokio::test]
    async fn save_delivery_receipt_persists_json_blob() {
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        store
            .enqueue_outbound_delivery("env-r", "https://peer.example")
            .await
            .unwrap();

        let receipt = r#"{"envelope_id":"env-r","received_at":"2026-…","receiver_relay_id":"amp:did:key:zPeer","signature":"ed25519:…|dilithium3:…"}"#;
        store
            .save_delivery_receipt("env-r", "https://peer.example", receipt)
            .await
            .unwrap();

        // Verify by reading the column directly. The `next_pending_delivery`
        // type doesn't include receipt_json; it's an admin-only field
        // surfaced by `GET /admin/deliveries/:envelope_id` (PR 2 of #32).
        let stored: Option<String> = store
            .conn
            .call(|c| {
                c.query_row(
                    "SELECT receipt_json FROM outbound_deliveries WHERE envelope_id = 'env-r'",
                    [],
                    |r| r.get::<_, Option<String>>(0),
                )
                .map_err(|e| e.into())
            })
            .await
            .unwrap();
        assert_eq!(stored.as_deref(), Some(receipt));
    }

    #[tokio::test]
    async fn save_delivery_receipt_is_a_no_op_for_unknown_row() {
        // The federation worker calls save_delivery_receipt only after
        // a successful delivery, so the row must exist. But if it
        // doesn't (e.g. a race where the row got expired between the
        // peer ACK and our write), we don't want a hard error — just
        // log via the caller. Storage layer just no-ops.
        let store = SqliteStore::open_in_memory().await.expect("sqlite");
        let r = store
            .save_delivery_receipt("not-here", "https://wherever", r#"{"x":1}"#)
            .await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn prekey_consumption_filestore_no_op_returns_stored() {
        let base = std::env::temp_dir().join(format!("aegis-relay-pk-fs-{}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&base).await;
        let store = FileStore::new(&base);

        let mut envelope = sample_envelope("amp:did:key:z6MkFsPk");
        envelope.used_prekey_ids = vec!["pk-irrelevant".to_string()];
        let outcome = store
            .store_with_prekey_consumption(&envelope)
            .await
            .expect("store");
        // FileStore is dev-only and does not enforce; documented behavior.
        assert_eq!(outcome, StoreOutcome::Stored);

        let _ = tokio::fs::remove_dir_all(&base).await;
    }
}
