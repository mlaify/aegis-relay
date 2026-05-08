use std::sync::Arc;

use aegis_api_types::{
    ClaimedPrekeyResponse, PublishPrekeysResponse, RelayError, RelayErrorResponse,
};
use aegis_identity::{verify_prekey_bundle_signature, ALG_ED25519, ALG_MLDSA65};
use aegis_proto::PrekeyBundle;
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::{
    audit::AuditEvent,
    routes::{require_auth, AuthScope},
    AppState,
};

/// `POST /v1/identities/:identity_id/prekeys`
///
/// Accepts a signed `PrekeyBundle`, verifies the signature against the
/// identity's already-published signing keys (Ed25519 + Dilithium3), and
/// inserts each one-time prekey into the unclaimed pool. Re-publishing is
/// idempotent — already-stored `(identity_id, key_id)` rows are kept as-is.
pub async fn publish_prekeys(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identity_id): Path<String>,
    payload: Result<Json<PrekeyBundle>, JsonRejection>,
) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::IdentityWrite) {
        return err.into_response();
    }

    let Json(bundle) = match payload {
        Ok(body) => body,
        Err(err) => {
            return bad_request("invalid_request", &err.body_text());
        }
    };

    if bundle.identity_id.0 != identity_id {
        return bad_request(
            "identity_id_mismatch",
            "identity_id in bundle must match URL path",
        );
    }

    if bundle.one_time_prekeys.is_empty() {
        return bad_request(
            "empty_bundle",
            "bundle must contain at least one one-time prekey",
        );
    }

    // Look up the identity's published signing keys to verify the bundle.
    let identity_doc = match state.store.fetch_identity(&identity_id).await {
        Ok(Some(doc)) => doc,
        Ok(None) => {
            return bad_request(
                "identity_not_published",
                "publish IdentityDocument before publishing PrekeyBundle",
            );
        }
        Err(_) => return internal_error("storage_error", "failed to fetch identity"),
    };

    if let Err(msg) = verify_bundle_signature(&bundle, &identity_doc) {
        return bad_request("invalid_signature", &msg);
    }

    match state.store.store_one_time_prekeys(&bundle).await {
        Ok(report) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "publish_prekeys",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: Some(&identity_id),
                    detail: Some(&format!(
                        "inserted={} skipped={}",
                        report.inserted, report.skipped
                    )),
                })
                .await;
            Json(PublishPrekeysResponse {
                identity_id,
                inserted: report.inserted,
                skipped: report.skipped,
            })
            .into_response()
        }
        Err(_) => internal_error("storage_error", "failed to store prekeys"),
    }
}

/// `GET /v1/identities/:identity_id/prekey`
///
/// Atomically claims one unclaimed one-time prekey for `identity_id`,
/// marks it consumed, and returns it. Returns `404 not_found` if the
/// unclaimed pool is empty.
pub async fn claim_prekey(
    State(state): State<Arc<AppState>>,
    Path(identity_id): Path<String>,
) -> Response {
    match state.store.claim_one_time_prekey(&identity_id).await {
        Ok(Some(claimed)) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "claim_prekey",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: Some(&identity_id),
                    detail: Some(&claimed.key_id),
                })
                .await;
            Json(ClaimedPrekeyResponse {
                identity_id: claimed.identity_id,
                key_id: claimed.key_id,
                algorithm: claimed.algorithm,
                public_key_b64: claimed.public_key_b64,
            })
            .into_response()
        }
        Ok(None) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "claim_prekey",
                    outcome: "exhausted",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: Some(&identity_id),
                    detail: None,
                })
                .await;
            (
                StatusCode::NOT_FOUND,
                Json(RelayErrorResponse {
                    error: RelayError {
                        code: "prekey_pool_empty".to_string(),
                        message: format!(
                            "no unclaimed one-time prekey available for {}",
                            identity_id
                        ),
                    },
                }),
            )
                .into_response()
        }
        Err(_) => internal_error("storage_error", "failed to claim prekey"),
    }
}

fn verify_bundle_signature(
    bundle: &PrekeyBundle,
    identity_doc: &aegis_proto::IdentityDocument,
) -> Result<(), String> {
    if bundle.signature.is_none() {
        return Err("prekey bundle must be self-signed before publishing".to_string());
    }

    let ed_record = identity_doc
        .signing_keys
        .iter()
        .find(|k| k.algorithm == ALG_ED25519)
        .ok_or_else(|| "identity document missing AMP-ED25519-V1 signing key".to_string())?;

    let dil_record = identity_doc
        .signing_keys
        .iter()
        .find(|k| k.algorithm == ALG_MLDSA65)
        .ok_or_else(|| "identity document missing AMP-MLDSA65-V1 signing key".to_string())?;

    let ed_vk_bytes = STANDARD
        .decode(&ed_record.public_key_b64)
        .map_err(|_| "invalid base64 in Ed25519 public key".to_string())?;
    let ed_vk: [u8; 32] = ed_vk_bytes
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_string())?;

    let dil_pk_bytes = STANDARD
        .decode(&dil_record.public_key_b64)
        .map_err(|_| "invalid base64 in Dilithium3 public key".to_string())?;

    verify_prekey_bundle_signature(bundle, &ed_vk, &dil_pk_bytes)
        .map_err(|_| "prekey bundle signature verification failed".to_string())
}

fn bad_request(code: &str, message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(RelayErrorResponse {
            error: RelayError {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

fn internal_error(code: &str, message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(RelayErrorResponse {
            error: RelayError {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aegis_crypto::HybridPqKeyBundle;
    use aegis_identity::{
        generate_prekey_bundle, sign_identity_document, sign_prekey_bundle, ALG_ED25519,
        ALG_MLDSA65, ALG_MLKEM768, ALG_X25519, SUITE_HYBRID_PQ,
    };
    use aegis_proto::{IdentityDocument, IdentityId, PublicKeyRecord};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::{get, post, put},
        Router,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tower::util::ServiceExt;

    use crate::AppState;
    use crate::{
        audit::AuditSink,
        config::RuntimeConfig,
        identity_routes,
        storage::SqliteStore,
    };

    /// Build an app router + a freshly generated identity bundle. The router
    /// has both identity and prekey routes wired so end-to-end flows work.
    async fn test_app_and_identity() -> (Router, IdentityId, HybridPqKeyBundle) {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("sqlite in-memory");
        let state = Arc::new(AppState {
            store: Arc::new(store),
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
            public_url: None,
            relay_identity: Arc::new(crate::relay_identity::generate().expect("test relay identity")),
            federation_discovery_cache: Arc::new(
                crate::federation_verify::DiscoveryCache::default_ttl(),
            ),
            federation_trusted_peers: None,
        });
        let app = Router::new()
            .route(
                "/v1/identities/:identity_id",
                put(identity_routes::put_identity),
            )
            .route(
                "/v1/identities/:identity_id",
                get(identity_routes::get_identity),
            )
            .route(
                "/v1/identities/:identity_id/prekeys",
                post(super::publish_prekeys),
            )
            .route(
                "/v1/identities/:identity_id/prekey",
                get(super::claim_prekey),
            )
            .with_state(state);

        let identity_keys = HybridPqKeyBundle::generate();
        let id = IdentityId(format!("amp:did:key:z6Mk{}", uuid_simple()));
        let mut doc = IdentityDocument {
            version: 1,
            identity_id: id.clone(),
            aliases: vec![],
            signing_keys: vec![
                PublicKeyRecord {
                    key_id: "sig-ed25519-1".to_string(),
                    algorithm: ALG_ED25519.to_string(),
                    public_key_b64: STANDARD.encode(identity_keys.ed25519_verifying_key_bytes),
                },
                PublicKeyRecord {
                    key_id: "sig-mldsa65-1".to_string(),
                    algorithm: ALG_MLDSA65.to_string(),
                    public_key_b64: STANDARD.encode(&identity_keys.dilithium3_public_key_bytes),
                },
            ],
            encryption_keys: vec![
                PublicKeyRecord {
                    key_id: "enc-x25519-1".to_string(),
                    algorithm: ALG_X25519.to_string(),
                    public_key_b64: STANDARD.encode(identity_keys.x25519_public_key_bytes),
                },
                PublicKeyRecord {
                    key_id: "enc-mlkem768-1".to_string(),
                    algorithm: ALG_MLKEM768.to_string(),
                    public_key_b64: STANDARD.encode(&identity_keys.kyber768_public_key_bytes),
                },
            ],
            supported_suites: vec![SUITE_HYBRID_PQ.to_string()],
            relay_endpoints: vec![],
            signature: None,
        };
        sign_identity_document(
            &mut doc,
            &identity_keys.ed25519_signing_seed_bytes,
            &identity_keys.dilithium3_secret_key_bytes,
        )
        .expect("sign identity");

        // Publish identity first; prekey publish requires the identity exist.
        let body = serde_json::to_string(&doc).unwrap();
        let req = Request::builder()
            .method("PUT")
            .uri(format!("/v1/identities/{}", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT, "publish identity");

        (app, id, identity_keys)
    }

    fn uuid_simple() -> String {
        // Avoid pulling rand or uuid as a test dep — derive a unique enough
        // suffix from a thread-local counter so concurrent tests don't collide.
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:016x}{:016x}", now, n)
    }

    fn url_encode(s: &str) -> String {
        s.replace(':', "%3A").replace('/', "%2F")
    }

    #[tokio::test]
    async fn publish_prekeys_end_to_end_then_claim_returns_one() {
        let (app, id, keys) = test_app_and_identity().await;
        let (mut bundle, _secrets) = generate_prekey_bundle(&id, 3, "ot");
        sign_prekey_bundle(
            &mut bundle,
            &keys.ed25519_signing_seed_bytes,
            &keys.dilithium3_secret_key_bytes,
        )
        .expect("sign bundle");

        let body = serde_json::to_string(&bundle).unwrap();
        let pub_req = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let pub_resp = app.clone().oneshot(pub_req).await.unwrap();
        assert_eq!(pub_resp.status(), StatusCode::OK);

        let pub_body = to_bytes(pub_resp.into_body(), usize::MAX).await.unwrap();
        let pub_json: serde_json::Value = serde_json::from_slice(&pub_body).unwrap();
        assert_eq!(pub_json["inserted"], 3);
        assert_eq!(pub_json["skipped"], 0);

        // Claim should succeed three times then return 404.
        for i in 0..3 {
            let claim_req = Request::builder()
                .method("GET")
                .uri(format!("/v1/identities/{}/prekey", url_encode(&id.0)))
                .body(Body::empty())
                .unwrap();
            let claim_resp = app.clone().oneshot(claim_req).await.unwrap();
            assert_eq!(claim_resp.status(), StatusCode::OK, "claim {}", i);
            let claim_body = to_bytes(claim_resp.into_body(), usize::MAX).await.unwrap();
            let claim_json: serde_json::Value = serde_json::from_slice(&claim_body).unwrap();
            assert_eq!(claim_json["algorithm"], "AMP-MLKEM768-V1");
            assert!(claim_json["key_id"].as_str().unwrap().starts_with("ot-"));
        }
        let exhausted_req = Request::builder()
            .method("GET")
            .uri(format!("/v1/identities/{}/prekey", url_encode(&id.0)))
            .body(Body::empty())
            .unwrap();
        let exhausted_resp = app.oneshot(exhausted_req).await.unwrap();
        assert_eq!(exhausted_resp.status(), StatusCode::NOT_FOUND);
        let body = to_bytes(exhausted_resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "prekey_pool_empty");
    }

    #[tokio::test]
    async fn republishing_bundle_is_idempotent() {
        let (app, id, keys) = test_app_and_identity().await;
        let (mut bundle, _) = generate_prekey_bundle(&id, 2, "ot");
        sign_prekey_bundle(
            &mut bundle,
            &keys.ed25519_signing_seed_bytes,
            &keys.dilithium3_secret_key_bytes,
        )
        .expect("sign");

        let body = serde_json::to_string(&bundle).unwrap();
        let first = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        let first_resp = app.clone().oneshot(first).await.unwrap();
        assert_eq!(first_resp.status(), StatusCode::OK);
        let first_body = to_bytes(first_resp.into_body(), usize::MAX).await.unwrap();
        let first_json: serde_json::Value = serde_json::from_slice(&first_body).unwrap();
        assert_eq!(first_json["inserted"], 2);

        let second = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let second_resp = app.oneshot(second).await.unwrap();
        assert_eq!(second_resp.status(), StatusCode::OK);
        let second_body = to_bytes(second_resp.into_body(), usize::MAX).await.unwrap();
        let second_json: serde_json::Value = serde_json::from_slice(&second_body).unwrap();
        assert_eq!(second_json["inserted"], 0);
        assert_eq!(second_json["skipped"], 2);
    }

    #[tokio::test]
    async fn publish_prekeys_rejects_unsigned_bundle() {
        let (app, id, _keys) = test_app_and_identity().await;
        let (bundle, _) = generate_prekey_bundle(&id, 1, "ot");
        // Intentionally NOT signing.
        assert!(bundle.signature.is_none());

        let body = serde_json::to_string(&bundle).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "invalid_signature");
    }

    #[tokio::test]
    async fn publish_prekeys_rejects_tampered_bundle() {
        let (app, id, keys) = test_app_and_identity().await;
        let (mut bundle, _) = generate_prekey_bundle(&id, 2, "ot");
        sign_prekey_bundle(
            &mut bundle,
            &keys.ed25519_signing_seed_bytes,
            &keys.dilithium3_secret_key_bytes,
        )
        .expect("sign");
        // Tamper after signing.
        bundle.one_time_prekeys.push(PublicKeyRecord {
            key_id: "ot-injected".to_string(),
            algorithm: ALG_MLKEM768.to_string(),
            public_key_b64: "AA==".to_string(),
        });

        let body = serde_json::to_string(&bundle).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "invalid_signature");
    }

    #[tokio::test]
    async fn publish_prekeys_rejects_when_identity_not_published() {
        let store = SqliteStore::open_in_memory().await.unwrap();
        let state = Arc::new(AppState {
            store: Arc::new(store),
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
            public_url: None,
            relay_identity: Arc::new(crate::relay_identity::generate().expect("test relay identity")),
            federation_discovery_cache: Arc::new(
                crate::federation_verify::DiscoveryCache::default_ttl(),
            ),
            federation_trusted_peers: None,
        });
        let app: Router = Router::new()
            .route(
                "/v1/identities/:identity_id/prekeys",
                post(super::publish_prekeys),
            )
            .with_state(state);

        let id = IdentityId("amp:did:key:z6MkOrphan".to_string());
        let keys = HybridPqKeyBundle::generate();
        let (mut bundle, _) = generate_prekey_bundle(&id, 1, "ot");
        sign_prekey_bundle(
            &mut bundle,
            &keys.ed25519_signing_seed_bytes,
            &keys.dilithium3_secret_key_bytes,
        )
        .unwrap();

        let body = serde_json::to_string(&bundle).unwrap();
        let req = Request::builder()
            .method("POST")
            .uri(format!("/v1/identities/{}/prekeys", url_encode(&id.0)))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"]["code"], "identity_not_published");
    }

    #[tokio::test]
    async fn claim_prekey_returns_404_when_pool_empty() {
        let (app, id, _keys) = test_app_and_identity().await;
        let req = Request::builder()
            .method("GET")
            .uri(format!("/v1/identities/{}/prekey", url_encode(&id.0)))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
