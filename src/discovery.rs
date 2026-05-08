//! Public client discovery endpoint: `GET /.well-known/aegis-config`.
//!
//! Returns a small JSON document advertising the relay's externally reachable
//! URL and the domain it serves so clients can resolve `user@domain` to a
//! concrete relay endpoint without manual configuration.
//!
//! No authentication: this is a discovery doc analogous to
//! `/.well-known/openid-configuration`.

use std::sync::Arc;

use axum::{
    extract::{Host, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct DiscoveryDocument {
    pub version: u8,
    /// Empty when no domains are claimed (relay is in open mode,
    /// receipts-only). Older clients that always read this field
    /// see "" rather than failing, which is a softer degradation
    /// than 404'ing the whole doc.
    pub domain: String,
    pub relay_url: String,
    pub supported_suites: Vec<&'static str>,
    pub policy: DiscoveryPolicy,
    /// Phase 6 (#32): the relay's own signed `IdentityDocument`.
    /// Senders fetch this once + cache; they verify delivery receipts
    /// against the `signing_keys` listed here. Older relays (no #32)
    /// omit this field — peers degrade gracefully to "receipt
    /// unverifiable, treat as opaque ack".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_identity: Option<aegis_proto::IdentityDocument>,
}

#[derive(Debug, Serialize)]
pub struct DiscoveryPolicy {
    /// "managed" when at least one verified domain is configured (alias gating
    /// in effect); "open" otherwise (any alias accepted).
    pub registration: &'static str,
    pub require_token_for_push: bool,
    pub require_token_for_identity_put: bool,
}

pub async fn well_known_aegis_config(
    State(state): State<Arc<AppState>>,
    Host(host_header): Host,
) -> Response {
    // Pull a generous slice to support orgs with many claimed domains;
    // discovery iterates over all verified entries and the cap mirrors
    // the admin API's per-page ceiling.
    let domains = match state.store.list_served_domains(0, 200).await {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "code": "storage_error", "message": "discovery lookup failed" }
                })),
            )
                .into_response();
        }
    };

    let verified: Vec<_> = domains.into_iter().filter(|d| d.verified_at.is_some()).collect();

    // Parse the persisted relay identity (signed at boot) and
    // expose its public document. Always present — every relay
    // generates one on first boot per #32 part 1. We swallow parse
    // failures rather than fail the whole discovery doc.
    let relay_identity_doc = crate::relay_identity::public_document(&state.relay_identity).ok();

    let host_lower = host_header.split(':').next().unwrap_or("").to_ascii_lowercase();
    let rt = state.runtime.read().unwrap();

    if verified.is_empty() {
        // Open-relay / receipts-only mode (#32): no claimed domains
        // but we DO have a signing identity. Advertise the identity
        // so peers can verify our receipts; leave the domain fields
        // empty so older clients see "no domain to publish under".
        let relay_url = state.public_url.clone().unwrap_or_default();
        return Json(DiscoveryDocument {
            version: 1,
            domain: String::new(),
            relay_url,
            supported_suites: vec!["AMP-PQ-1"],
            policy: DiscoveryPolicy {
                registration: "open",
                require_token_for_push: rt.require_token_for_push,
                require_token_for_identity_put: rt.require_token_for_identity_put,
            },
            relay_identity: relay_identity_doc,
        })
        .into_response();
    }

    // Pick the domain that matches the request Host header if any of the
    // claimed domains appear in it; otherwise fall back to the first verified
    // domain (the canonical one for this relay).
    let chosen = verified
        .iter()
        .find(|d| host_lower == d.domain || host_lower.ends_with(&format!(".{}", d.domain)))
        .unwrap_or(&verified[0])
        .clone();

    let relay_url = state
        .public_url
        .clone()
        .unwrap_or_else(|| format!("https://{}", chosen.domain));

    let registration = "managed";

    Json(DiscoveryDocument {
        version: 1,
        domain: chosen.domain,
        relay_url,
        supported_suites: vec!["AMP-PQ-1"],
        policy: DiscoveryPolicy {
            registration,
            require_token_for_push: rt.require_token_for_push,
            require_token_for_identity_put: rt.require_token_for_identity_put,
        },
        relay_identity: relay_identity_doc,
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditSink;
    use crate::config::RuntimeConfig;
    use crate::storage::SqliteStore;
    use axum::{routing::get, Router};
    use tower::ServiceExt;

    async fn build_state() -> Arc<AppState> {
        let store = SqliteStore::open_in_memory().await.unwrap();
        Arc::new(AppState {
            store: Arc::new(store),
            runtime: Arc::new(std::sync::RwLock::new(RuntimeConfig {
                tokens: vec![],
                require_token_for_push: false,
                require_token_for_identity_put: true,
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            })),
            admin_token: None,
            audit: AuditSink::new(None),
            runtime_config_path: std::path::PathBuf::from("/tmp/test-runtime.json"),
            public_url: Some("https://relay.example.test".into()),
            relay_identity: Arc::new(crate::relay_identity::generate().expect("test relay identity")),
            federation_discovery_cache: Arc::new(
                crate::federation_verify::DiscoveryCache::default_ttl(),
            ),
            federation_trusted_peers: None,
        })
    }

    fn router(state: Arc<AppState>) -> Router {
        Router::new()
            .route("/.well-known/aegis-config", get(well_known_aegis_config))
            .with_state(state)
    }

    #[tokio::test]
    async fn discovery_returns_relay_identity_even_without_verified_domain() {
        // Pre-#32 this returned 404. Post-#32 a relay always has a
        // signing identity (generated at first boot) — discovery has
        // to expose those keys so peers can verify our receipts even
        // before any domain has been claimed.
        //
        // The doc still indicates "no domain claimed" via empty
        // string and `policy.registration = "open"`; older clients
        // that always read the domain field see "" rather than
        // exploding.
        let state = build_state().await;
        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/aegis-config")
                    .header("host", "example.test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 32_768).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["domain"], "");
        assert_eq!(json["policy"]["registration"], "open");
        // Relay identity present + has signing keys — that's the
        // whole point of returning a doc here.
        assert!(json["relay_identity"].is_object(), "{json}");
        assert!(
            json["relay_identity"]["signing_keys"].is_array(),
            "expected signing_keys array in relay_identity, got {}",
            json["relay_identity"]
        );
    }

    #[tokio::test]
    async fn discovery_returns_doc_for_verified_domain() {
        let state = build_state().await;
        state
            .store
            .add_served_domain("example.test", "tok-1")
            .await
            .unwrap();
        state
            .store
            .mark_domain_verified("example.test")
            .await
            .unwrap();

        let app = router(state);
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/aegis-config")
                    .header("host", "example.test")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        // 32 KiB headroom — the response now embeds the relay's full
        // signed identity document including the ML-DSA-65 public key
        // (~1.9 KiB on its own) since #32, so the historical 8 KiB cap
        // overflows.
        let body = axum::body::to_bytes(resp.into_body(), 32_768).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["domain"], "example.test");
        assert_eq!(json["relay_url"], "https://relay.example.test");
        assert_eq!(json["version"], 1);
    }
}
