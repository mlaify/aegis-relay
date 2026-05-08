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
        let client = match reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(format!(
                "aegis-relay/{} federation",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(target: "federation", error = %e, "failed to build HTTP client; federation disabled");
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
