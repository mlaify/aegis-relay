//! Phase 5 — relay-to-relay federation (push delivery). Tracking ticket:
//! mlaify/aegis-relay#28.
//!
//! When this relay stores an envelope addressed to a recipient whose
//! `IdentityDocument.relay_endpoints` contains a relay URL OTHER than
//! our own, we push-deliver the envelope to that relay using its public
//! `POST /v1/envelopes` endpoint — the same wire format senders use, so
//! no new endpoints or formats are introduced.
//!
//! Loop prevention:
//!   - The sender filters out its own `public_url` before enqueueing,
//!     so we never schedule a delivery to ourselves.
//!   - Outbound POSTs carry `X-Aegis-Forwarded: true`. The receiver checks
//!     this header in `routes::store_envelope` and skips re-enqueueing —
//!     federated envelopes are terminal.
//!
//! Trust:
//!   - We do NOT decrypt the envelope. It's forwarded as the same opaque
//!     blob the sender produced. The receiving relay's existing
//!     `store_envelope` validation runs end-to-end.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::json;

use crate::AppState;

/// The HTTP header that marks an inbound envelope as "delivered via
/// federation; do not re-federate". Receiver short-circuits the
/// `maybe_enqueue` path when this is present.
pub const FORWARDED_HEADER: &str = "x-aegis-forwarded";

/// Default cap on retry attempts. Configurable via
/// `AEGIS_FEDERATION_MAX_ATTEMPTS`. After this many failures the row is
/// marked `expired` and the local envelope copy is left in place for the
/// operator to investigate.
const DEFAULT_MAX_ATTEMPTS: u32 = 7;

/// Default cap on how many `relay_endpoints` we'll fan out to for a single
/// envelope. Configurable via `AEGIS_FEDERATION_MAX_TARGETS_PER_ENVELOPE`.
/// A misconfigured `IdentityDocument` listing dozens of relays could
/// otherwise DoS the queue with redundant deliveries; capping at 4 keeps
/// the common-case "primary + 1-2 backups" working without trusting the
/// recipient's count.
const DEFAULT_MAX_TARGETS: usize = 4;

/// How long to nap when the queue is empty. Short enough that newly-
/// enqueued items get picked up quickly, long enough that we don't burn
/// CPU on a busy-loop poll.
const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// HTTP request timeout per delivery attempt. Federation peers are
/// expected to respond quickly; longer than this and the network has
/// likely failed.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Backoff schedule indexed by attempt count (0-based). Returns the
/// delay before the *next* attempt — pure function so it's easy to test.
///
/// 0 → 0s   (first attempt, scheduled immediately on enqueue)
/// 1 → 1m
/// 2 → 5m
/// 3 → 15m
/// 4 → 1h
/// 5 → 6h
/// 6 → 24h
/// 7+ → out of attempts → caller marks expired
pub fn next_backoff(attempts: u32) -> Option<Duration> {
    let secs = match attempts {
        0 => 0,
        1 => 60,
        2 => 5 * 60,
        3 => 15 * 60,
        4 => 60 * 60,
        5 => 6 * 60 * 60,
        6 => 24 * 60 * 60,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

/// Resolve the list of remote relays to which this envelope should be
/// federated. Returns up to `max_targets` URLs in the recipient's
/// published preference order, with our own `public_url` filtered out
/// (loop prevention) and duplicates collapsed.
///
/// Multi-target failover (#30): when an `IdentityDocument` lists
/// multiple `relay_endpoints`, we enqueue ONE outbound delivery per
/// target. Each delivery row tracks its own attempt count + backoff;
/// the FIRST one to succeed marks its siblings as `superseded` so
/// they're not retried after the envelope has already landed somewhere.
pub fn targets_for(
    relay_endpoints: &[String],
    self_public_url: Option<&str>,
    max_targets: usize,
) -> Vec<String> {
    let normalized_self = self_public_url.map(normalize_url);
    let mut out: Vec<String> = Vec::new();
    for ep in relay_endpoints {
        if out.len() >= max_targets {
            break;
        }
        let ep_norm = normalize_url(ep);
        if Some(&ep_norm) == normalized_self.as_ref() {
            continue;
        }
        if !out.contains(&ep_norm) {
            out.push(ep_norm);
        }
    }
    out
}

fn max_targets_per_envelope() -> usize {
    std::env::var("AEGIS_FEDERATION_MAX_TARGETS_PER_ENVELOPE")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_TARGETS)
}

/// Lower-case + strip any trailing slash so trivial differences in how
/// `relay_endpoints` are rendered (`HTTPS://...` vs `https://.../`) don't
/// break self-detection.
fn normalize_url(url: &str) -> String {
    let s = url.trim().trim_end_matches('/').to_ascii_lowercase();
    s
}

/// Called from `routes::store_envelope` after a successful local store.
/// Resolves the recipient's `IdentityDocument`, computes targets, and
/// enqueues delivery rows. Errors are logged + swallowed — federation
/// failures must not surface as `POST /v1/envelopes` failures (the
/// envelope IS stored locally; the worker will keep retrying in the
/// background).
pub async fn maybe_enqueue(state: &AppState, envelope_id: &str, recipient_id: &str) {
    let identity = match state.store.fetch_identity(recipient_id).await {
        Ok(Some(doc)) => doc,
        Ok(None) => return, // unknown recipient: store-and-fetch model handles it
        Err(e) => {
            tracing::warn!(
                target: "federation",
                error = %e,
                recipient_id,
                "fetch_identity failed during enqueue; skipping"
            );
            return;
        }
    };

    let targets = targets_for(
        &identity.relay_endpoints,
        state.public_url.as_deref(),
        max_targets_per_envelope(),
    );
    if targets.is_empty() {
        return;
    }

    for target in targets {
        if let Err(e) = state
            .store
            .enqueue_outbound_delivery(envelope_id, &target)
            .await
        {
            tracing::warn!(
                target: "federation",
                error = %e,
                envelope_id,
                target = %target,
                "enqueue_outbound_delivery failed"
            );
        } else {
            tracing::info!(
                target: "federation",
                envelope_id,
                target = %target,
                "enqueued"
            );
        }
    }
}

/// Spawn the long-running delivery worker. Called once from `main` after
/// `AppState` is built. Returns the JoinHandle so tests can drop it.
pub fn spawn_delivery_worker(state: Arc<AppState>) -> tokio::task::JoinHandle<()> {
    let max_attempts = std::env::var("AEGIS_FEDERATION_MAX_ATTEMPTS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(DEFAULT_MAX_ATTEMPTS);

    tokio::spawn(async move {
        // Phase 6 (#32 part 3): pull mTLS / custom-CA config from env at
        // worker start. A misconfig (e.g. missing key file, malformed
        // PEM) is reported once at boot and the worker exits — better
        // than silently downgrading to anonymous federation when an
        // operator asked for client-cert auth.
        let client = match build_http_client_from_env() {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    target: "federation",
                    error = %e,
                    "failed to build HTTP client; federation disabled"
                );
                return;
            }
        };

        loop {
            match state.store.next_pending_delivery().await {
                Ok(Some(delivery)) => {
                    deliver_one(&state, &client, max_attempts, &delivery).await;
                    // Don't sleep on success — drain the queue greedily.
                }
                Ok(None) => {
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
                Err(e) => {
                    tracing::error!(target: "federation", error = %e, "next_pending_delivery failed");
                    tokio::time::sleep(IDLE_POLL_INTERVAL).await;
                }
            }
        }
    })
}

/// Run one delivery attempt against the queue row in `delivery`. Public
/// to the crate so tests can drive a single iteration without spinning
/// up the long-running worker (avoids racing on the `IDLE_POLL_INTERVAL`
/// sleep).
pub(crate) async fn deliver_one(
    state: &AppState,
    client: &reqwest::Client,
    max_attempts: u32,
    delivery: &crate::storage::OutboundDelivery,
) {
    // Phase 6 (#32 part 2): pre-flight peer trust check. Fetch the
    // peer's discovery doc (cached), confirm we can read a hybrid
    // signing identity from it, then enforce the trusted-peer
    // allowlist if one is configured. Failures here mark the row
    // expired without ever sending the envelope — the operator's
    // explicit "I don't trust this peer" decision must short-circuit
    // before any data leaves the host.
    let peer_doc = match crate::federation_verify::fetch_peer_identity(
        &state.federation_discovery_cache,
        client,
        &delivery.target_url,
    )
    .await
    {
        Ok(doc) => Some(doc),
        Err(crate::federation_verify::FederationVerifyError::PeerHasNoIdentity) => {
            // Peer is on an older version (#32 part 1 not deployed
            // there yet). We have to choose: refuse, or push without
            // verification. v0 chooses "push without verification" so
            // graceful upgrade across the fleet is possible — the
            // sender stores no receipt for this delivery, surfaces
            // that fact in audit log + metrics. If an operator has
            // configured the allowlist, we DO refuse below because
            // we can't confirm peer identity to enforce the list.
            if state.federation_trusted_peers.is_some() {
                let detail = format!(
                    "peer {} has no relay_identity in /.well-known/aegis-config; \
                     cannot enforce AEGIS_FEDERATION_TRUSTED_PEERS",
                    delivery.target_url
                );
                tracing::warn!(target: "federation", envelope_id = %delivery.envelope_id, "{}", detail);
                state
                    .audit
                    .record(crate::audit::AuditEvent {
                        at: Utc::now(),
                        operation: "federation_expired",
                        outcome: "untrusted_peer",
                        recipient_id: None,
                        envelope_id: Some(&delivery.envelope_id),
                        identity_id: None,
                        detail: Some(&detail),
                    })
                    .await;
                let _ = state
                    .store
                    .mark_delivery_expired(&delivery.envelope_id, &delivery.target_url)
                    .await;
                return;
            }
            None
        }
        Err(e) => {
            // Discovery fetch failed — transient by default (DNS,
            // network), retry with backoff. The sender doesn't
            // distinguish "peer is down" from "peer is misconfigured"
            // here; both end up in the retry schedule.
            tracing::warn!(
                target: "federation",
                error = %e,
                target_url = %delivery.target_url,
                "discovery fetch failed; will retry"
            );
            schedule_retry(state, max_attempts, delivery, &format!("discovery: {}", e)).await;
            return;
        }
    };

    // Allowlist check. Skipped only when the peer has no identity
    // AND the operator hasn't asked for strict federation (handled
    // above — we returned early when `trusted_peers.is_some()` and the
    // peer had no identity).
    if let Some(doc) = &peer_doc {
        let allowlist = state.federation_trusted_peers.as_deref();
        if !crate::federation_verify::is_peer_trusted(allowlist, &doc.identity_id.0) {
            let detail = format!(
                "peer {} (id={}) is not in AEGIS_FEDERATION_TRUSTED_PEERS",
                delivery.target_url, doc.identity_id.0
            );
            tracing::warn!(
                target: "federation",
                envelope_id = %delivery.envelope_id,
                "{}",
                detail
            );
            state
                .audit
                .record(crate::audit::AuditEvent {
                    at: Utc::now(),
                    operation: "federation_expired",
                    outcome: "untrusted_peer",
                    recipient_id: None,
                    envelope_id: Some(&delivery.envelope_id),
                    identity_id: None,
                    detail: Some(&detail),
                })
                .await;
            let _ = state
                .store
                .mark_delivery_expired(&delivery.envelope_id, &delivery.target_url)
                .await;
            return;
        }
    }

    // Reload the envelope from local storage so we forward the EXACT
    // bytes the sender pushed (signature canonicalization is byte-
    // sensitive). If the envelope is gone (already delivered + expired,
    // or admin purged) we skip and mark expired.
    let envelope_json = match state
        .store
        .fetch_envelope_json(&delivery.envelope_id)
        .await
    {
        Ok(Some(json)) => json,
        Ok(None) => {
            tracing::info!(
                target: "federation",
                envelope_id = %delivery.envelope_id,
                target = %delivery.target_url,
                "envelope no longer in local store; marking expired"
            );
            let _ = state
                .store
                .mark_delivery_expired(&delivery.envelope_id, &delivery.target_url)
                .await;
            return;
        }
        Err(e) => {
            tracing::warn!(
                target: "federation",
                error = %e,
                envelope_id = %delivery.envelope_id,
                "fetch_envelope_json failed during deliver; will retry"
            );
            schedule_retry(state, max_attempts, delivery, "envelope read failed").await;
            return;
        }
    };

    let body = json!({ "envelope": serde_json::from_str::<serde_json::Value>(&envelope_json).unwrap_or(serde_json::Value::Null) });

    let url = format!("{}/v1/envelopes", delivery.target_url.trim_end_matches('/'));

    let resp = client
        .post(&url)
        .header(FORWARDED_HEADER, "true")
        .header(reqwest::header::CONTENT_TYPE, "application/json")
        .header(reqwest::header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let status = r.status();
            // Phase 6 (#32): try to capture the signed receipt the peer
            // returned in the response body. We pull the body as JSON
            // and extract the optional `receipt` object — if the peer
            // is on an older relay version they won't return one, and
            // we treat that as "ack OK, no proof on file". Receipt
            // VALIDATION (verifying the signature against the peer's
            // published identity) is the work in #32 part 2; this PR
            // only persists what the peer says.
            let receipt_json: Option<String> = match r.text().await {
                Ok(text) => extract_receipt_field(&text),
                Err(e) => {
                    tracing::warn!(
                        target: "federation",
                        error = %e,
                        envelope_id = %delivery.envelope_id,
                        "could not read response body; treating as ack-only"
                    );
                    None
                }
            };
            tracing::info!(
                target: "federation",
                envelope_id = %delivery.envelope_id,
                target = %delivery.target_url,
                status = %status,
                has_receipt = receipt_json.is_some(),
                "delivered"
            );
            state
                .audit
                .record(crate::audit::AuditEvent {
                    at: Utc::now(),
                    operation: "federation_delivered",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: Some(&delivery.envelope_id),
                    identity_id: None,
                    detail: Some(&format!(
                        "{} receipt={}",
                        delivery.target_url,
                        if receipt_json.is_some() { "yes" } else { "no" },
                    )),
                })
                .await;
            if let Some(rj) = &receipt_json {
                // Phase 6 (#32 part 2): verify the receipt against the
                // peer's published signing keys before persisting.
                // Verification failures invalidate the discovery cache
                // (so the next attempt re-fetches and picks up any
                // legitimate key rotation) and mark the row as
                // expired — the peer claimed acceptance but couldn't
                // prove it, which is a security event the operator
                // should investigate.
                if let Some(doc) = &peer_doc {
                    match serde_json::from_str::<crate::relay_identity::DeliveryReceipt>(rj)
                        .map_err(|e| crate::federation_verify::FederationVerifyError::CanonicalEncode(e.to_string()))
                        .and_then(|r| crate::federation_verify::verify_receipt(&r, doc))
                    {
                        Ok(()) => {
                            tracing::info!(
                                target: "federation",
                                envelope_id = %delivery.envelope_id,
                                target = %delivery.target_url,
                                "receipt verified"
                            );
                            state
                                .audit
                                .record(crate::audit::AuditEvent {
                                    at: Utc::now(),
                                    operation: "federation_receipt_verified",
                                    outcome: "ok",
                                    recipient_id: None,
                                    envelope_id: Some(&delivery.envelope_id),
                                    identity_id: None,
                                    detail: Some(&delivery.target_url),
                                })
                                .await;
                        }
                        Err(e) => {
                            // Don't trust this peer for the next round;
                            // forces a discovery re-fetch.
                            state
                                .federation_discovery_cache
                                .invalidate(&delivery.target_url);
                            let detail = format!(
                                "{} verify_failed={}",
                                delivery.target_url, e
                            );
                            tracing::warn!(
                                target: "federation",
                                envelope_id = %delivery.envelope_id,
                                "receipt verification failed: {}",
                                e
                            );
                            state
                                .audit
                                .record(crate::audit::AuditEvent {
                                    at: Utc::now(),
                                    operation: "federation_receipt_verify_failed",
                                    outcome: "rejected",
                                    recipient_id: None,
                                    envelope_id: Some(&delivery.envelope_id),
                                    identity_id: None,
                                    detail: Some(&detail),
                                })
                                .await;
                            let _ = state
                                .store
                                .mark_delivery_expired(
                                    &delivery.envelope_id,
                                    &delivery.target_url,
                                )
                                .await;
                            return;
                        }
                    }
                }
                if let Err(e) = state
                    .store
                    .save_delivery_receipt(&delivery.envelope_id, &delivery.target_url, rj)
                    .await
                {
                    tracing::warn!(
                        target: "federation",
                        error = %e,
                        envelope_id = %delivery.envelope_id,
                        "save_delivery_receipt failed; receipt is not persisted but delivery succeeded"
                    );
                }
            }
            match state
                .store
                .mark_delivery_delivered(&delivery.envelope_id, &delivery.target_url)
                .await
            {
                Ok(superseded) => {
                    // Multi-target failover (#30): siblings that were
                    // still pending when this delivery succeeded are
                    // now collapsed. Audit-log each one explicitly so
                    // operators can grep for which target won and
                    // which got skipped without re-running the SQL.
                    for sibling in &superseded {
                        tracing::info!(
                            target: "federation",
                            envelope_id = %delivery.envelope_id,
                            superseded_target = %sibling,
                            winner = %delivery.target_url,
                            "sibling delivery superseded by successful peer"
                        );
                        state
                            .audit
                            .record(crate::audit::AuditEvent {
                                at: Utc::now(),
                                operation: "federation_superseded",
                                outcome: "ok",
                                recipient_id: None,
                                envelope_id: Some(&delivery.envelope_id),
                                identity_id: None,
                                detail: Some(&format!(
                                    "{} winner={}",
                                    sibling, delivery.target_url
                                )),
                            })
                            .await;
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: "federation",
                        error = %e,
                        envelope_id = %delivery.envelope_id,
                        "mark_delivery_delivered failed"
                    );
                }
            }
        }
        Ok(r) if r.status().is_client_error() => {
            // 4xx from peer: probably a permanent rejection (bad
            // envelope, recipient unknown to peer). Don't retry.
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            tracing::warn!(
                target: "federation",
                envelope_id = %delivery.envelope_id,
                target = %delivery.target_url,
                status = %status,
                body = %truncate(&body, 200),
                "peer rejected with 4xx; expiring delivery"
            );
            state
                .audit
                .record(crate::audit::AuditEvent {
                    at: Utc::now(),
                    operation: "federation_expired",
                    outcome: "rejected",
                    recipient_id: None,
                    envelope_id: Some(&delivery.envelope_id),
                    identity_id: None,
                    detail: Some(&format!(
                        "{} status={} body={}",
                        delivery.target_url,
                        status,
                        truncate(&body, 200)
                    )),
                })
                .await;
            let _ = state
                .store
                .mark_delivery_expired(&delivery.envelope_id, &delivery.target_url)
                .await;
        }
        Ok(r) => {
            // 5xx: transient — retry with backoff.
            let status = r.status();
            let body = r.text().await.unwrap_or_default();
            schedule_retry(
                state,
                max_attempts,
                delivery,
                &format!("HTTP {} {}", status, truncate(&body, 200)),
            )
            .await;
        }
        Err(e) => {
            // Connection/TLS/timeout — retry.
            schedule_retry(state, max_attempts, delivery, &format!("transport: {}", e)).await;
        }
    }
}

async fn schedule_retry(
    state: &AppState,
    max_attempts: u32,
    delivery: &crate::storage::OutboundDelivery,
    error: &str,
) {
    let next_attempt = delivery.attempts + 1;
    let backoff = next_backoff(next_attempt);

    let outcome = match backoff {
        Some(_) if next_attempt >= max_attempts => "expired",
        Some(_) => "retry",
        None => "expired",
    };

    tracing::warn!(
        target: "federation",
        envelope_id = %delivery.envelope_id,
        target = %delivery.target_url,
        attempt = next_attempt,
        error,
        outcome,
        "delivery attempt failed"
    );

    state
        .audit
        .record(crate::audit::AuditEvent {
            at: Utc::now(),
            operation: "federation_attempt",
            outcome,
            recipient_id: None,
            envelope_id: Some(&delivery.envelope_id),
            identity_id: None,
            detail: Some(&format!(
                "{} attempt={} error={}",
                delivery.target_url,
                next_attempt,
                truncate(error, 200)
            )),
        })
        .await;

    if outcome == "expired" {
        let _ = state
            .store
            .mark_delivery_expired(&delivery.envelope_id, &delivery.target_url)
            .await;
        return;
    }

    let next_at: DateTime<Utc> = Utc::now() + chrono::Duration::from_std(backoff.unwrap()).unwrap();
    let _ = state
        .store
        .mark_delivery_attempt(&delivery.envelope_id, &delivery.target_url, error, next_at)
        .await;
}

/// Pull the optional `receipt` JSON out of the peer's
/// `StoreEnvelopeResponse` body without round-tripping through a typed
/// struct. Keeps the wire format relaxed: a peer running an older
/// relay (no receipt at all) returns `None`; one running #32 returns
/// a `serde_json::Value` we re-stringify for storage.
///
/// We deliberately don't validate the receipt's signature here — that
/// stage ships in #32 part 2 once we've also done discovery-doc
/// fetching. For PR 1, persisting the bytes is enough.
fn extract_receipt_field(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    let receipt = v.get("receipt")?;
    if receipt.is_null() {
        return None;
    }
    serde_json::to_string(receipt).ok()
}

// --- HTTP client construction (#32 part 3 mTLS) ----------------------------

/// Errors surfaced when building the federation HTTP client. Distinct
/// type so the boot path can log a structured reason rather than a
/// generic `reqwest::Error`.
#[derive(Debug)]
pub enum FederationClientError {
    /// Cert path set but key path missing (or vice-versa). mTLS needs
    /// both; refuse to start in a half-configured state rather than
    /// silently fall back to anonymous federation.
    IncompleteMtlsConfig,
    /// Couldn't read one of the configured PEM files.
    PemRead { path: String, source: std::io::Error },
    /// Failed to parse a PEM blob (cert, key, or CA bundle).
    PemDecode(String),
    /// Underlying reqwest builder failure (TLS engine setup etc.).
    Reqwest(reqwest::Error),
}

impl std::fmt::Display for FederationClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IncompleteMtlsConfig => write!(
                f,
                "AEGIS_FEDERATION_CLIENT_CERT_PATH and AEGIS_FEDERATION_CLIENT_KEY_PATH \
                 must both be set, or both unset"
            ),
            Self::PemRead { path, source } => write!(f, "read {path}: {source}"),
            Self::PemDecode(s) => write!(f, "PEM decode: {s}"),
            Self::Reqwest(e) => write!(f, "reqwest: {e}"),
        }
    }
}

impl std::error::Error for FederationClientError {}

/// Read mTLS / CA-bundle config from process env and build the
/// federation HTTP client. Convenience wrapper that defers to
/// `build_http_client_with` so tests can inject paths without
/// `std::env::set_var` racing.
pub fn build_http_client_from_env() -> Result<reqwest::Client, FederationClientError> {
    let cert = std::env::var("AEGIS_FEDERATION_CLIENT_CERT_PATH").ok();
    let key = std::env::var("AEGIS_FEDERATION_CLIENT_KEY_PATH").ok();
    let ca = std::env::var("AEGIS_FEDERATION_CA_BUNDLE_PATH").ok();
    build_http_client_with(cert.as_deref(), key.as_deref(), ca.as_deref())
}

/// Construct the federation HTTP client with optional sender-side mTLS
/// (client cert presented during the TLS handshake) and an optional
/// custom CA bundle for verifying peer TLS certs.
///
/// Both `cert_path` and `key_path` must be `Some` together for mTLS to
/// activate. A half-configured state (one set, one not) is treated as
/// a hard error so misconfig is loud at startup rather than silent at
/// federation time.
///
/// `ca_path` is independent — operators using a private/internal CA
/// for their relay-to-relay TLS (vs. publicly-trusted certs) can point
/// at the bundle without enabling mTLS.
pub fn build_http_client_with(
    cert_path: Option<&str>,
    key_path: Option<&str>,
    ca_path: Option<&str>,
) -> Result<reqwest::Client, FederationClientError> {
    let mut builder = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!(
            "aegis-relay/{} federation",
            env!("CARGO_PKG_VERSION")
        ));

    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            // reqwest's rustls-tls feature exposes `Identity::from_pem`
            // which expects a single PEM blob containing BOTH cert and
            // key. We keep the two-file env-var UX (operators rarely
            // have a single combined PEM — Let's Encrypt + most CAs
            // hand out separate fullchain.pem + privkey.pem) by
            // reading both files and concatenating in-memory.
            let cert_pem = std::fs::read(cert_path).map_err(|e| {
                FederationClientError::PemRead {
                    path: cert_path.to_string(),
                    source: e,
                }
            })?;
            let key_pem = std::fs::read(key_path).map_err(|e| {
                FederationClientError::PemRead {
                    path: key_path.to_string(),
                    source: e,
                }
            })?;
            let combined = concat_pem(&cert_pem, &key_pem);
            let identity = reqwest::Identity::from_pem(&combined)
                .map_err(|e| FederationClientError::PemDecode(e.to_string()))?;
            builder = builder.identity(identity);
            tracing::info!(
                target: "federation",
                cert_path,
                "mTLS client cert loaded; outbound federation will present it during TLS handshake"
            );
        }
        (None, None) => {
            // Default: no mTLS. Federation pushes use whatever auth
            // the receiving relay's HTTP layer requires (bearer token,
            // CF Access JWT, or nothing).
        }
        _ => return Err(FederationClientError::IncompleteMtlsConfig),
    }

    if let Some(ca_path) = ca_path {
        let ca_pem = std::fs::read(ca_path).map_err(|e| FederationClientError::PemRead {
            path: ca_path.to_string(),
            source: e,
        })?;
        let cert = reqwest::Certificate::from_pem(&ca_pem)
            .map_err(|e| FederationClientError::PemDecode(e.to_string()))?;
        builder = builder.add_root_certificate(cert);
        tracing::info!(
            target: "federation",
            ca_path,
            "added custom CA root for peer TLS verification"
        );
    }

    builder.build().map_err(FederationClientError::Reqwest)
}

/// Concatenate cert + key PEM blobs into the single buffer
/// `Identity::from_pem` expects. Inserts a newline between them if
/// the cert blob doesn't end with one — defensive against PEM files
/// missing a trailing LF (some tooling produces these).
fn concat_pem(cert_pem: &[u8], key_pem: &[u8]) -> Vec<u8> {
    let mut combined = Vec::with_capacity(cert_pem.len() + key_pem.len() + 1);
    combined.extend_from_slice(cert_pem);
    if !cert_pem.ends_with(b"\n") {
        combined.push(b'\n');
    }
    combined.extend_from_slice(key_pem);
    combined
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::Mutex;

    use aegis_api_types::{StoreEnvelopeRequest, StoreEnvelopeResponse};
    use aegis_proto::{
        EncryptedBlob, Envelope, IdentityDocument, IdentityId, PublicKeyRecord, SuiteId,
    };
    use axum::extract::State;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};

    use crate::audit::AuditSink;
    use crate::config::RuntimeConfig;
    use crate::storage::{Store, SqliteStore};
    use crate::AppState;

    /// One-shot mock that records every inbound `POST /v1/envelopes` —
    /// enough to assert the federation worker forwards correctly.
    #[derive(Default, Debug)]
    struct RecordedRequest {
        forwarded_header: Option<String>,
        envelope_id: String,
        recipient_id: String,
    }

    type Recorder = Arc<Mutex<Vec<RecordedRequest>>>;

    async fn mock_remote_store(
        State(rec): State<Recorder>,
        headers: HeaderMap,
        Json(req): Json<StoreEnvelopeRequest>,
    ) -> Json<StoreEnvelopeResponse> {
        let forwarded = headers
            .get(FORWARDED_HEADER)
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        rec.lock().unwrap().push(RecordedRequest {
            forwarded_header: forwarded,
            envelope_id: req.envelope.envelope_id.0.to_string(),
            recipient_id: req.envelope.recipient_id.0.clone(),
        });
        Json(StoreEnvelopeResponse {
            accepted: true,
            relay_id: "mock-remote".into(),
        })
    }

    async fn spawn_mock_remote() -> (String, Recorder) {
        let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new()
            .route("/v1/envelopes", post(mock_remote_store))
            .with_state(recorder.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{}", addr), recorder)
    }

    fn sample_identity_doc(id: &str, relay_endpoints: Vec<String>) -> IdentityDocument {
        IdentityDocument {
            version: 1,
            identity_id: IdentityId(id.to_string()),
            aliases: vec![],
            signing_keys: vec![PublicKeyRecord {
                key_id: format!("{}-sign", id),
                algorithm: "AMP-ED25519-V1".to_string(),
                public_key_b64: "AAAA".to_string(),
            }],
            encryption_keys: vec![PublicKeyRecord {
                key_id: format!("{}-x25519", id),
                algorithm: "AMP-X25519-V1".to_string(),
                public_key_b64: "BBBB".to_string(),
            }],
            supported_suites: vec!["AMP-DEMO-XCHACHA20POLY1305".to_string()],
            relay_endpoints,
            signature: None,
        }
    }

    fn sample_envelope_for(recipient: &str) -> Envelope {
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

    async fn make_state(
        public_url: Option<String>,
        store: Arc<SqliteStore>,
    ) -> Arc<AppState> {
        Arc::new(AppState {
            store,
            runtime: Arc::new(std::sync::RwLock::new(RuntimeConfig {
                tokens: vec![],
                require_token_for_push: false,
                require_token_for_identity_put: false,
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            })),
            admin_token: None,
            audit: AuditSink::new(None),
            runtime_config_path: std::path::PathBuf::from("/tmp/test-runtime.json"),
            public_url,
            relay_identity: Arc::new(crate::relay_identity::generate().expect("test relay identity")),
            federation_discovery_cache: Arc::new(
                crate::federation_verify::DiscoveryCache::default_ttl(),
            ),
            federation_trusted_peers: None,
        })
    }

    // --- Pure-function tests --------------------------------------------

    #[test]
    fn backoff_schedule_matches_spec() {
        assert_eq!(next_backoff(0), Some(Duration::from_secs(0)));
        assert_eq!(next_backoff(1), Some(Duration::from_secs(60)));
        assert_eq!(next_backoff(2), Some(Duration::from_secs(5 * 60)));
        assert_eq!(next_backoff(3), Some(Duration::from_secs(15 * 60)));
        assert_eq!(next_backoff(4), Some(Duration::from_secs(60 * 60)));
        assert_eq!(next_backoff(5), Some(Duration::from_secs(6 * 60 * 60)));
        assert_eq!(next_backoff(6), Some(Duration::from_secs(24 * 60 * 60)));
        assert_eq!(next_backoff(7), None);
        assert_eq!(next_backoff(99), None);
    }

    #[test]
    fn targets_skip_self_url() {
        let endpoints = vec![
            "https://relay.company-a.com/".to_string(),
            "https://relay.company-b.com".to_string(),
        ];
        let targets =
            targets_for(&endpoints, Some("https://relay.company-a.com"), DEFAULT_MAX_TARGETS);
        assert_eq!(targets, vec!["https://relay.company-b.com".to_string()]);
    }

    #[test]
    fn targets_returns_all_non_self_in_preference_order() {
        // #30: federation now fans out to ALL non-self entries (up to
        // max_targets), in published preference order.
        let endpoints = vec![
            "https://relay-1.example".to_string(),
            "https://relay-2.example".to_string(),
            "https://relay-3.example".to_string(),
        ];
        let targets = targets_for(&endpoints, None, DEFAULT_MAX_TARGETS);
        assert_eq!(
            targets,
            vec![
                "https://relay-1.example".to_string(),
                "https://relay-2.example".to_string(),
                "https://relay-3.example".to_string(),
            ]
        );
    }

    #[test]
    fn targets_capped_at_max_targets() {
        // Caller's max_targets caps the fanout — guards against a
        // misconfigured doc with dozens of relay_endpoints.
        let endpoints: Vec<String> = (0..10)
            .map(|i| format!("https://relay-{}.example", i))
            .collect();
        let targets = targets_for(&endpoints, None, 3);
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0], "https://relay-0.example");
        assert_eq!(targets[2], "https://relay-2.example");
    }

    #[test]
    fn targets_self_filter_does_not_count_against_cap() {
        // The cap applies AFTER self-filter, so a doc with [self, A, B,
        // C, D] returns [A, B, C, D] up to max — self isn't a "wasted"
        // slot.
        let endpoints = vec![
            "https://us.example".to_string(),
            "https://a.example".to_string(),
            "https://b.example".to_string(),
            "https://c.example".to_string(),
        ];
        let targets = targets_for(&endpoints, Some("https://us.example"), 3);
        assert_eq!(
            targets,
            vec![
                "https://a.example".to_string(),
                "https://b.example".to_string(),
                "https://c.example".to_string(),
            ]
        );
    }

    #[test]
    fn targets_empty_when_only_self() {
        let endpoints = vec!["https://us.example".to_string()];
        let targets = targets_for(&endpoints, Some("https://us.example/"), DEFAULT_MAX_TARGETS);
        assert!(targets.is_empty());
    }

    #[test]
    fn targets_empty_when_no_endpoints() {
        let targets = targets_for(&[], Some("https://us.example"), DEFAULT_MAX_TARGETS);
        assert!(targets.is_empty());
    }

    #[test]
    fn url_normalization_strips_trailing_slash_and_lowercases() {
        let endpoints = vec!["HTTPS://Relay.Example.COM/".to_string()];
        let targets =
            targets_for(&endpoints, Some("https://relay.example.com"), DEFAULT_MAX_TARGETS);
        assert!(
            targets.is_empty(),
            "self-loop should be detected after case-insensitive normalize, got {:?}",
            targets
        );
    }

    // --- End-to-end with a mock remote relay ----------------------------

    // --- Receipt extraction (mlaify/aegis-relay#32) ----------------------

    #[test]
    fn extract_receipt_field_pulls_object_from_response_body() {
        let body = r#"{
            "accepted": true,
            "relay_id": "amp:did:key:zRelayPeer",
            "receipt": {
                "envelope_id": "env-1",
                "received_at": "2026-05-08T03:14:15Z",
                "receiver_relay_id": "amp:did:key:zRelayPeer",
                "signature": "ed25519:abc|dilithium3:def"
            }
        }"#;
        let extracted = extract_receipt_field(body).expect("receipt present");
        // Round-trip: must parse back to a JSON object with the same keys.
        let v: serde_json::Value = serde_json::from_str(&extracted).unwrap();
        assert_eq!(v["envelope_id"], "env-1");
        assert!(v["signature"].as_str().unwrap().starts_with("ed25519:"));
    }

    #[test]
    fn extract_receipt_field_returns_none_for_missing_field() {
        // Older relays (pre-#32) won't include `receipt` at all.
        // Sender treats this as "ack OK, no receipt on file".
        let body = r#"{"accepted": true, "relay_id": "old-relay"}"#;
        assert!(extract_receipt_field(body).is_none());
    }

    #[test]
    fn extract_receipt_field_returns_none_for_explicit_null() {
        // `"receipt": null` is semantically the same as missing.
        // Defensive parse path so we don't store the literal string "null".
        let body = r#"{"accepted": true, "relay_id": "old-relay", "receipt": null}"#;
        assert!(extract_receipt_field(body).is_none());
    }

    #[test]
    fn extract_receipt_field_returns_none_for_garbage_body() {
        // If the body isn't JSON at all (proxy error page, etc.), we
        // shouldn't panic — just yield None and let the caller log.
        assert!(extract_receipt_field("502 bad gateway").is_none());
        assert!(extract_receipt_field("").is_none());
    }

    // --- mTLS client construction (#32 part 3) -----------------------------

    #[test]
    fn http_client_builds_with_no_mtls_config() {
        // Default: no env vars set → anonymous federation, builder
        // succeeds. Mirrors the steady-state pre-#32-part-3 behavior.
        let client = build_http_client_with(None, None, None);
        assert!(client.is_ok(), "default client should build, got {:?}", client.err());
    }

    #[test]
    fn http_client_rejects_half_configured_mtls() {
        // Cert without key, or key without cert, is a misconfig.
        // Hard error so operators see the bad config at boot rather
        // than discovering it only when federation fails to handshake.
        let cert_only = build_http_client_with(Some("/tmp/cert.pem"), None, None);
        assert!(matches!(
            cert_only,
            Err(FederationClientError::IncompleteMtlsConfig)
        ), "cert-only config should error, got {:?}", cert_only);

        let key_only = build_http_client_with(None, Some("/tmp/key.pem"), None);
        assert!(matches!(
            key_only,
            Err(FederationClientError::IncompleteMtlsConfig)
        ), "key-only config should error, got {:?}", key_only);
    }

    #[test]
    fn http_client_surfaces_missing_cert_file() {
        // Both env vars set but the cert file doesn't exist on disk.
        // Should report the path so the operator knows what to fix.
        let result = build_http_client_with(
            Some("/tmp/aegis-test-does-not-exist-cert.pem"),
            Some("/tmp/aegis-test-does-not-exist-key.pem"),
            None,
        );
        match result {
            Err(FederationClientError::PemRead { path, .. }) => {
                assert_eq!(path, "/tmp/aegis-test-does-not-exist-cert.pem");
            }
            other => panic!("expected PemRead error for missing cert, got {:?}", other),
        }
    }

    #[test]
    fn http_client_surfaces_pem_decode_failure() {
        // Both files exist but the cert PEM is malformed. Operator
        // should see a clear "PEM decode" error rather than a
        // generic builder failure.
        use std::io::Write;

        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!(
            "aegis-test-mtls-bad-cert-{}.pem",
            std::process::id()
        ));
        let key_path = dir.join(format!(
            "aegis-test-mtls-bad-key-{}.pem",
            std::process::id()
        ));
        std::fs::File::create(&cert_path)
            .unwrap()
            .write_all(b"not a real PEM")
            .unwrap();
        std::fs::File::create(&key_path)
            .unwrap()
            .write_all(b"not a real PEM either")
            .unwrap();

        let result = build_http_client_with(
            Some(cert_path.to_str().unwrap()),
            Some(key_path.to_str().unwrap()),
            None,
        );

        // Cleanup before assertions so a panic doesn't strand /tmp files.
        let _ = std::fs::remove_file(&cert_path);
        let _ = std::fs::remove_file(&key_path);

        assert!(
            matches!(result, Err(FederationClientError::PemDecode(_))),
            "expected PemDecode for malformed PEM, got {:?}",
            result
        );
    }

    #[test]
    fn http_client_ca_bundle_independent_of_mtls() {
        // Custom CA without mTLS is a valid config (operator using a
        // private CA for peer TLS verification but not presenting a
        // client cert). Builder should not require mTLS env vars
        // when CA is set.
        let result = build_http_client_with(None, None, Some("/tmp/aegis-test-no-such-ca.pem"));
        match result {
            Err(FederationClientError::PemRead { path, .. }) => {
                // Got past the mTLS-config check, failed on the
                // missing CA file — exactly what we want.
                assert_eq!(path, "/tmp/aegis-test-no-such-ca.pem");
            }
            other => panic!(
                "expected PemRead for missing CA, got {:?} (CA path should be checked independently of mTLS)",
                other
            ),
        }
    }

    #[test]
    fn concat_pem_inserts_newline_when_cert_lacks_trailing_lf() {
        // PEM concatenation must ensure the key's "-----BEGIN PRIVATE
        // KEY-----" doesn't get glued onto the cert's final line.
        let cert = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----";
        let key = b"-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----\n";
        let combined = concat_pem(cert, key);
        let combined_str = String::from_utf8(combined).unwrap();
        assert!(combined_str.contains("-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----"));
    }

    #[test]
    fn concat_pem_does_not_double_newline_when_already_terminated() {
        // If the cert PEM already ends with LF, don't add another.
        let cert = b"-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n";
        let key = b"-----BEGIN PRIVATE KEY-----\nXYZ\n-----END PRIVATE KEY-----\n";
        let combined = concat_pem(cert, key);
        let combined_str = String::from_utf8(combined).unwrap();
        // Exactly one newline between the two blocks.
        assert!(combined_str.contains("-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----"));
        assert!(!combined_str.contains("-----END CERTIFICATE-----\n\n-----BEGIN PRIVATE KEY-----"));
    }

    #[tokio::test]
    async fn maybe_enqueue_skips_when_recipient_only_lists_self() {
        // This relay's own URL is the only entry on the recipient's
        // identity doc — federation must be a no-op (we ARE the
        // authoritative relay).
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zSelfRecipient";
        store
            .store_identity(&sample_identity_doc(
                recipient,
                vec!["https://us.example".to_string()],
            ))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &env.envelope_id.0.to_string(), recipient).await;

        let pending = store.next_pending_delivery().await.unwrap();
        assert!(
            pending.is_none(),
            "no delivery should be queued when only target is self"
        );
    }

    #[tokio::test]
    async fn maybe_enqueue_creates_row_for_remote_endpoint() {
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zRemoteRecipient";
        store
            .store_identity(&sample_identity_doc(
                recipient,
                vec!["https://peer.example".to_string()],
            ))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let pending = store.next_pending_delivery().await.unwrap().unwrap();
        assert_eq!(pending.envelope_id, envelope_id);
        assert_eq!(pending.target_url, "https://peer.example");
        assert_eq!(pending.attempts, 0);
    }

    #[tokio::test]
    async fn maybe_enqueue_creates_row_per_remote_endpoint() {
        // #30: with multiple relay_endpoints, each gets its own row.
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zMultiTarget";
        store
            .store_identity(&sample_identity_doc(
                recipient,
                vec![
                    "https://peer-1.example".to_string(),
                    "https://peer-2.example".to_string(),
                    "https://peer-3.example".to_string(),
                ],
            ))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        // Drain the queue; should produce three pending rows (one per
        // target). Order is by next_retry_at which is identical at
        // enqueue time → use a set to compare.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for _ in 0..3 {
            let row = store
                .next_pending_delivery()
                .await
                .unwrap()
                .expect("pending row");
            seen.insert(row.target_url.clone());
            // Push each retrieved row out of the way by scheduling its
            // next attempt in the future, so the next loop iteration
            // returns a different row.
            store
                .mark_delivery_attempt(
                    &row.envelope_id,
                    &row.target_url,
                    "test-skip",
                    Utc::now() + chrono::Duration::hours(1),
                )
                .await
                .unwrap();
        }
        assert_eq!(
            seen,
            ["https://peer-1.example", "https://peer-2.example", "https://peer-3.example"]
                .iter()
                .map(|s| s.to_string())
                .collect()
        );
    }

    #[tokio::test]
    async fn first_successful_delivery_supersedes_pending_siblings() {
        // The headline #30 behavior: when one target succeeds, the
        // others stop being attempted. Set up three pending rows for
        // the same envelope, then mark one delivered and verify the
        // others flip to 'superseded'.
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let env = sample_envelope_for("amp:did:key:zSibSupRecipient");
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        for target in [
            "https://peer-1.example",
            "https://peer-2.example",
            "https://peer-3.example",
        ] {
            store
                .enqueue_outbound_delivery(&envelope_id, target)
                .await
                .unwrap();
        }

        // Mark the middle one delivered.
        let superseded = store
            .mark_delivery_delivered(&envelope_id, "https://peer-2.example")
            .await
            .unwrap();

        let mut sup_set: std::collections::HashSet<String> = superseded.into_iter().collect();
        assert!(sup_set.remove("https://peer-1.example"));
        assert!(sup_set.remove("https://peer-3.example"));
        assert!(sup_set.is_empty(), "extra siblings reported: {:?}", sup_set);

        // Nothing pending — the other two are 'superseded', not
        // 'pending' — so the worker won't pick them up again.
        let next = store.next_pending_delivery().await.unwrap();
        assert!(next.is_none(), "no rows should be pending, got {:?}", next);

        // Local envelope is purged.
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(local.is_none());
    }

    #[tokio::test]
    async fn delivery_failures_dont_supersede_other_targets() {
        // Counterpoint: marking ONE delivery expired (failure) does
        // NOT affect the others. They keep retrying independently.
        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let env = sample_envelope_for("amp:did:key:zIndependentFailures");
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        for target in ["https://peer-1.example", "https://peer-2.example"] {
            store
                .enqueue_outbound_delivery(&envelope_id, target)
                .await
                .unwrap();
        }

        store
            .mark_delivery_expired(&envelope_id, "https://peer-1.example")
            .await
            .unwrap();

        // peer-2 must still be available for the worker to pick up.
        let next = store
            .next_pending_delivery()
            .await
            .unwrap()
            .expect("peer-2 still pending");
        assert_eq!(next.target_url, "https://peer-2.example");

        // Local envelope must NOT be purged on a single-target
        // expiration (only on success).
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(local.is_some());
    }

    #[tokio::test]
    async fn multi_target_e2e_first_success_wins_others_superseded() {
        // End-to-end: three peers, two return 503, one returns 200.
        // Verifies the integrated behavior — worker drains the queue,
        // hits the failures (which schedule retries), and when the
        // succeeding peer ACKs the failed siblings flip to superseded.
        let (good_url, good_recorder) = spawn_mock_remote().await;

        // Two "down" peers that always 503.
        async fn always_503() -> (axum::http::StatusCode, &'static str) {
            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "down")
        }
        let down_a = Router::new().route("/v1/envelopes", post(always_503));
        let down_b = Router::new().route("/v1/envelopes", post(always_503));
        let l_a = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a_addr = l_a.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l_a, down_a).await;
        });
        let l_b = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let b_addr = l_b.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(l_b, down_b).await;
        });
        let down_a_url = format!("http://{}", a_addr);
        let down_b_url = format!("http://{}", b_addr);

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zMultiE2E";
        // Order matters — published preference order. Working peer is
        // last so we exercise the failures-before-success path.
        store
            .store_identity(&sample_identity_doc(
                recipient,
                vec![down_a_url.clone(), down_b_url.clone(), good_url.clone()],
            ))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        // Drain everything that's "due now" from the queue. The
        // worker normally loops forever; we simulate one drain pass
        // here. Order matches whatever next_pending_delivery picks
        // first — irrelevant because every pending row is due.
        for _ in 0..3 {
            let Some(due) = store.next_pending_delivery().await.unwrap() else {
                break;
            };
            deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;
        }

        // The good peer received exactly one POST (the winning one).
        let recv = good_recorder.lock().unwrap();
        assert_eq!(recv.len(), 1, "good peer should receive exactly one POST");
        assert_eq!(recv[0].forwarded_header.as_deref(), Some("true"));
        drop(recv);

        // Local envelope is gone.
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(local.is_none(), "envelope should be purged on first ACK");

        // No more pending deliveries — failed siblings either retried
        // (but pushed to future) and superseded by the winner.
        let nothing = store.next_pending_delivery().await.unwrap();
        assert!(nothing.is_none());
    }

    #[tokio::test]
    async fn deliver_one_pushes_with_forwarded_header_and_purges_local() {
        // End-to-end: real HTTP roundtrip from federation worker to a
        // mock peer. Verifies the X-Aegis-Forwarded header is set, the
        // peer receives the envelope, and the local copy is dropped on
        // success ACK.
        let (remote_url, recorder) = spawn_mock_remote().await;

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zFederationE2E";
        store
            .store_identity(&sample_identity_doc(recipient, vec![remote_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        // Drive the worker by hand for one tick so we don't have to
        // race against IDLE_POLL_INTERVAL.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // Mock peer received exactly one POST with the forwarded header.
        let recv = recorder.lock().unwrap();
        assert_eq!(recv.len(), 1, "expected one forwarded delivery");
        assert_eq!(recv[0].envelope_id, envelope_id);
        assert_eq!(recv[0].recipient_id, recipient);
        assert_eq!(recv[0].forwarded_header.as_deref(), Some("true"));
        drop(recv);

        // Local envelope was expired on ACK.
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(
            local.is_none(),
            "local envelope should be gone after delivery ACK"
        );

        // No more pending deliveries (status now 'delivered').
        let after = store.next_pending_delivery().await.unwrap();
        assert!(after.is_none());
    }

    #[tokio::test]
    async fn deliver_one_retries_on_5xx_until_max_attempts() {
        // Spin up a peer that always returns 503 — the worker should
        // schedule retries until DEFAULT_MAX_ATTEMPTS, then mark expired.
        let app = Router::new().route(
            "/v1/envelopes",
            post(|| async {
                (
                    axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    "peer is down",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let remote_url = format!("http://{}", addr);

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zRetry";
        store
            .store_identity(&sample_identity_doc(recipient, vec![remote_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();

        // First attempt: 5xx → backoff scheduled, attempt count 1.
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // Row still exists, status still pending, but next_retry_at in
        // the future so it's not "due".
        let next = store.next_pending_delivery().await.unwrap();
        assert!(
            next.is_none(),
            "5xx response should leave row pending but not due, got {:?}",
            next
        );

        // Local envelope must NOT be deleted on a transient failure.
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(local.is_some(), "envelope must persist across retries");
    }

    /// Build a mini "peer relay" that serves both the discovery doc
    /// (with the peer's identity_id and signing keys) AND
    /// `POST /v1/envelopes` returning a properly-signed receipt.
    /// Used by the #32 part 2 end-to-end tests so they exercise the
    /// real verify path without standing up a full second relay.
    async fn spawn_authentic_peer() -> (
        String,
        crate::storage::RelayIdentity,
        Recorder,
    ) {
        let identity = crate::relay_identity::generate().expect("peer identity");
        let identity_for_router = identity.clone();
        let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
        let recorder_for_router = recorder.clone();

        // /.well-known/aegis-config → relay_identity-bearing doc.
        let identity_for_discovery = identity.clone();
        let discovery_handler = move || {
            let doc = crate::relay_identity::public_document(&identity_for_discovery)
                .expect("public doc");
            async move {
                axum::Json(serde_json::json!({
                    "version": 1,
                    "domain": "",
                    "relay_url": "",
                    "supported_suites": ["AMP-PQ-1"],
                    "policy": {
                        "registration": "open",
                        "require_token_for_push": false,
                        "require_token_for_identity_put": false,
                    },
                    "relay_identity": doc,
                }))
            }
        };

        // /v1/envelopes → 200 OK with a real signed receipt.
        let envelope_handler = move |State(rec): State<(Recorder, crate::storage::RelayIdentity)>,
                                     headers: HeaderMap,
                                     Json(req): Json<StoreEnvelopeRequest>| async move {
            let forwarded = headers
                .get(FORWARDED_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            rec.0.lock().unwrap().push(RecordedRequest {
                forwarded_header: forwarded,
                envelope_id: req.envelope.envelope_id.0.to_string(),
                recipient_id: req.envelope.recipient_id.0.clone(),
            });
            let received_at = chrono::Utc::now().to_rfc3339();
            let receipt = crate::relay_identity::sign_receipt(
                &rec.1,
                &req.envelope.envelope_id.0.to_string(),
                &received_at,
            )
            .expect("sign receipt");
            Json(serde_json::json!({
                "accepted": true,
                "relay_id": rec.1.identity_id,
                "receipt": receipt,
            }))
        };

        let envelope_state = (recorder_for_router, identity_for_router.clone());
        let app = Router::new()
            .route("/.well-known/aegis-config", axum::routing::get(discovery_handler))
            .route(
                "/v1/envelopes",
                post(envelope_handler).with_state(envelope_state),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{}", addr), identity, recorder)
    }

    #[tokio::test]
    async fn delivery_to_authentic_peer_verifies_and_persists_receipt() {
        // End-to-end #32 part 2: sender pushes envelope, peer returns
        // a real signed receipt, sender's worker fetches peer's
        // discovery doc + verifies the signature + persists the
        // receipt blob. The whole flow runs in-process against a
        // local axum mock peer.
        let (peer_url, _peer_identity, peer_recorder) = spawn_authentic_peer().await;

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zReceiptVerifyRecipient";
        store
            .store_identity(&sample_identity_doc(recipient, vec![peer_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // Peer received the POST.
        let recv = peer_recorder.lock().unwrap();
        assert_eq!(recv.len(), 1);
        drop(recv);

        // Local envelope purged (delivery succeeded).
        assert!(store.fetch_envelope_json(&envelope_id).await.unwrap().is_none());

        // Receipt persisted in outbound_deliveries.
        let rows = store.list_deliveries_for_envelope(&envelope_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "delivered");
        assert!(
            rows[0].receipt_json.is_some(),
            "verified receipt should be persisted"
        );
        // It's well-formed JSON describing a DeliveryReceipt.
        let receipt: serde_json::Value =
            serde_json::from_str(rows[0].receipt_json.as_ref().unwrap()).unwrap();
        assert_eq!(receipt["envelope_id"], envelope_id);
        assert!(receipt["signature"].as_str().unwrap().starts_with("ed25519:"));
    }

    #[tokio::test]
    async fn delivery_refused_when_peer_not_in_allowlist() {
        // Operator has set AEGIS_FEDERATION_TRUSTED_PEERS. The peer
        // serves a valid discovery doc with its own identity_id, but
        // it's NOT in our allowlist. The sender must refuse pre-flight
        // and never push the envelope.
        let (peer_url, _peer_identity, peer_recorder) = spawn_authentic_peer().await;

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zAllowlistRecipient";
        store
            .store_identity(&sample_identity_doc(recipient, vec![peer_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let mut state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        // SAFETY: state is the only Arc; no other clones yet.
        let mutable = Arc::get_mut(&mut state).expect("unique Arc");
        mutable.federation_trusted_peers =
            Some(vec!["amp:did:key:zNotThisPeer".to_string()]);
        let state = state;

        maybe_enqueue(&state, &envelope_id, recipient).await;
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // Peer received NO POST — refusal happened pre-flight.
        let recv = peer_recorder.lock().unwrap();
        assert_eq!(recv.len(), 0, "allowlist refusal should never push");
        drop(recv);

        // Row marked expired with no further retries.
        let rows = store.list_deliveries_for_envelope(&envelope_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "expired");
    }

    #[tokio::test]
    async fn delivery_marks_expired_when_receipt_verification_fails() {
        // Peer is reachable + serves discovery, but its receipt is
        // forged (signed by someone else). Sender should detect the
        // mismatch, invalidate cache, and mark the row expired.
        // Mock returns a "receipt" object whose signature won't
        // verify against the doc the discovery endpoint published.

        let bogus_identity = crate::relay_identity::generate().expect("bogus");
        let advertised_identity = crate::relay_identity::generate().expect("advertised");

        let recorder: Recorder = Arc::new(Mutex::new(Vec::new()));
        let recorder_for_route = recorder.clone();

        // /.well-known/aegis-config → advertised_identity
        let advertised_for_disc = advertised_identity.clone();
        let discovery = move || {
            let doc = crate::relay_identity::public_document(&advertised_for_disc).unwrap();
            async move {
                axum::Json(serde_json::json!({
                    "version": 1,
                    "domain": "",
                    "relay_url": "",
                    "supported_suites": ["AMP-PQ-1"],
                    "policy": {
                        "registration": "open",
                        "require_token_for_push": false,
                        "require_token_for_identity_put": false,
                    },
                    "relay_identity": doc,
                }))
            }
        };

        // /v1/envelopes → returns a receipt SIGNED BY bogus_identity
        // but claiming to be from advertised_identity. Classic forge.
        let envelope_handler = move |State((rec, bogus, advertised)): State<(
            Recorder,
            crate::storage::RelayIdentity,
            crate::storage::RelayIdentity,
        )>,
                                     headers: HeaderMap,
                                     Json(req): Json<StoreEnvelopeRequest>| async move {
            let forwarded = headers
                .get(FORWARDED_HEADER)
                .and_then(|v| v.to_str().ok())
                .map(String::from);
            rec.lock().unwrap().push(RecordedRequest {
                forwarded_header: forwarded,
                envelope_id: req.envelope.envelope_id.0.to_string(),
                recipient_id: req.envelope.recipient_id.0.clone(),
            });
            // Sign with bogus identity but claim to be `advertised`.
            let mut receipt = crate::relay_identity::sign_receipt(
                &bogus,
                &req.envelope.envelope_id.0.to_string(),
                &chrono::Utc::now().to_rfc3339(),
            )
            .unwrap();
            receipt.receiver_relay_id = advertised.identity_id.clone();
            Json(serde_json::json!({
                "accepted": true,
                "relay_id": advertised.identity_id,
                "receipt": receipt,
            }))
        };

        let env_state = (
            recorder_for_route,
            bogus_identity,
            advertised_identity.clone(),
        );
        let app = Router::new()
            .route("/.well-known/aegis-config", axum::routing::get(discovery))
            .route("/v1/envelopes", post(envelope_handler).with_state(env_state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zForgedRecipient";
        store
            .store_identity(&sample_identity_doc(recipient, vec![peer_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // Peer received the POST — refusal happens AFTER it returns
        // the forged receipt, not before.
        let recv = recorder.lock().unwrap();
        assert_eq!(recv.len(), 1);
        drop(recv);

        // Verification failed → row is expired, NOT delivered.
        let rows = store.list_deliveries_for_envelope(&envelope_id).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].status, "expired",
            "forged receipt should expire the delivery, got {:?}",
            rows[0]
        );
        // Receipt was NOT persisted — we don't keep evidence of forgery.
        assert!(rows[0].receipt_json.is_none());
    }

    #[tokio::test]
    async fn deliver_one_marks_expired_on_4xx_immediately() {
        let app = Router::new().route(
            "/v1/envelopes",
            post(|| async {
                (
                    axum::http::StatusCode::BAD_REQUEST,
                    "{\"error\":{\"code\":\"invalid_envelope\"}}",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        let remote_url = format!("http://{}", addr);

        let store = Arc::new(SqliteStore::open_in_memory().await.unwrap());
        let recipient = "amp:did:key:zReject";
        store
            .store_identity(&sample_identity_doc(recipient, vec![remote_url.clone()]))
            .await
            .unwrap();
        let env = sample_envelope_for(recipient);
        let envelope_id = env.envelope_id.0.to_string();
        store.store(&env).await.unwrap();

        let state = make_state(Some("https://us.example".to_string()), store.clone()).await;
        maybe_enqueue(&state, &envelope_id, recipient).await;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let due = store.next_pending_delivery().await.unwrap().unwrap();
        deliver_one(&state, &client, DEFAULT_MAX_ATTEMPTS, &due).await;

        // 4xx: expired immediately, no further retries.
        let next = store.next_pending_delivery().await.unwrap();
        assert!(next.is_none(), "4xx should expire the row, not retry");

        // Local envelope preserved (we only purge on successful ACK).
        let local = store.fetch_envelope_json(&envelope_id).await.unwrap();
        assert!(local.is_some());
    }
}
