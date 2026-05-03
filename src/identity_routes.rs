use std::sync::Arc;

use aegis_api_types::{RelayError, RelayErrorResponse};
use aegis_identity::{verify_identity_document_signature, ALG_ED25519, ALG_MLDSA65};
use aegis_proto::IdentityDocument;
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

pub async fn put_identity(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(identity_id): Path<String>,
    payload: Result<Json<IdentityDocument>, JsonRejection>,
) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::IdentityWrite) {
        return err.into_response();
    }

    let Json(doc) = match payload {
        Ok(doc) => doc,
        Err(err) => {
            return bad_request("invalid_request", &err.body_text());
        }
    };

    if doc.identity_id.0 != identity_id {
        return bad_request(
            "identity_id_mismatch",
            "identity_id in document must match URL path",
        );
    }

    // The relay enforces self-certification: every stored IdentityDocument must
    // carry a valid Ed25519 + Dilithium3 signature over its own public keys.
    if let Err(msg) = verify_doc_signature(&doc) {
        return bad_request("invalid_signature", &msg);
    }

    match state.store.store_identity(&doc).await {
        Ok(()) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "put_identity",
                    outcome: "ok",
                    recipient_id: None,
                    envelope_id: None,
                    identity_id: Some(&identity_id),
                    detail: None,
                })
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(_) => internal_error("storage_error", "failed to store identity"),
    }
}

pub async fn get_identity(
    State(state): State<Arc<AppState>>,
    Path(identity_id): Path<String>,
) -> Response {
    match state.store.fetch_identity(&identity_id).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(RelayErrorResponse {
                error: RelayError {
                    code: "not_found".to_string(),
                    message: format!("identity {} not found", identity_id),
                },
            }),
        )
            .into_response(),
        Err(_) => internal_error("storage_error", "failed to fetch identity"),
    }
}

pub async fn get_alias(State(state): State<Arc<AppState>>, Path(alias): Path<String>) -> Response {
    match state.store.resolve_alias(&alias).await {
        Ok(Some(doc)) => Json(doc).into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(RelayErrorResponse {
                error: RelayError {
                    code: "not_found".to_string(),
                    message: format!("alias {} not found", alias),
                },
            }),
        )
            .into_response(),
        Err(_) => internal_error("storage_error", "failed to resolve alias"),
    }
}

fn verify_doc_signature(doc: &IdentityDocument) -> Result<(), String> {
    if doc.signature.is_none() {
        return Err("identity document must be self-signed before publishing".to_string());
    }

    let ed_record = doc
        .signing_keys
        .iter()
        .find(|k| k.algorithm == ALG_ED25519)
        .ok_or_else(|| "identity document missing AMP-ED25519-V1 signing key".to_string())?;

    let dil_record = doc
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

    verify_identity_document_signature(doc, &ed_vk, &dil_pk_bytes)
        .map_err(|_| "identity document signature verification failed".to_string())
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
        sign_identity_document, ALG_ED25519, ALG_MLDSA65, ALG_MLKEM768, ALG_X25519, SUITE_HYBRID_PQ,
    };
    use aegis_proto::{IdentityDocument, IdentityId, PublicKeyRecord};
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::{get, put},
        Router,
    };
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use tower::util::ServiceExt;

    use crate::AppState;
    use crate::{
        audit::AuditSink,
        config::{AuthMode, RelayAuthConfig, RetentionPolicy},
        storage::SqliteStore,
    };

    async fn test_app() -> Router {
        test_app_with_token(None).await
    }

    async fn test_app_with_token(token: Option<&str>) -> Router {
        let store = SqliteStore::open_in_memory()
            .await
            .expect("sqlite in-memory");
        let state = Arc::new(AppState {
            store: Arc::new(store),
            auth: RelayAuthConfig {
                mode: if token.is_some() {
                    AuthMode::Token
                } else {
                    AuthMode::Open
                },
                tokens: token.map(|t| vec![t.to_string()]).unwrap_or_default(),
                require_token_for_push: false,
                require_token_for_identity_put: true,
            },
            retention: RetentionPolicy {
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            },
            audit: AuditSink::new(None),
        });
        Router::new()
            .route("/v1/identities/:identity_id", put(super::put_identity))
            .route("/v1/identities/:identity_id", get(super::get_identity))
            .route("/v1/aliases/:alias", get(super::get_alias))
            .with_state(state)
    }

    fn make_signed_doc(identity_id: &str) -> IdentityDocument {
        make_signed_doc_with_aliases(identity_id, vec![])
    }

    fn make_signed_doc_with_aliases(identity_id: &str, aliases: Vec<String>) -> IdentityDocument {
        let bundle = HybridPqKeyBundle::generate();
        let mut doc = IdentityDocument {
            version: 1,
            identity_id: IdentityId(identity_id.to_string()),
            aliases,
            signing_keys: vec![
                PublicKeyRecord {
                    key_id: "sig-ed25519-1".to_string(),
                    algorithm: ALG_ED25519.to_string(),
                    public_key_b64: STANDARD.encode(bundle.ed25519_verifying_key_bytes),
                },
                PublicKeyRecord {
                    key_id: "sig-mldsa65-1".to_string(),
                    algorithm: ALG_MLDSA65.to_string(),
                    public_key_b64: STANDARD.encode(&bundle.dilithium3_public_key_bytes),
                },
            ],
            encryption_keys: vec![
                PublicKeyRecord {
                    key_id: "enc-x25519-1".to_string(),
                    algorithm: ALG_X25519.to_string(),
                    public_key_b64: STANDARD.encode(bundle.x25519_public_key_bytes),
                },
                PublicKeyRecord {
                    key_id: "enc-mlkem768-1".to_string(),
                    algorithm: ALG_MLKEM768.to_string(),
                    public_key_b64: STANDARD.encode(&bundle.kyber768_public_key_bytes),
                },
            ],
            supported_suites: vec![SUITE_HYBRID_PQ.to_string()],
            relay_endpoints: vec![],
            signature: None,
        };
        sign_identity_document(
            &mut doc,
            &bundle.ed25519_signing_seed_bytes,
            &bundle.dilithium3_secret_key_bytes,
        )
        .expect("sign");
        doc
    }

    #[tokio::test]
    async fn put_signed_identity_returns_no_content() {
        let app = test_app().await;
        let doc = make_signed_doc("amp:did:key:z6MkTest");
        let body = serde_json::to_string(&doc).unwrap();

        let req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkTest")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn put_identity_requires_token_when_configured() {
        let app = test_app_with_token(Some("dev-token")).await;
        let doc = make_signed_doc("amp:did:key:z6MkProtected");
        let body = serde_json::to_string(&doc).unwrap();

        let missing_req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkProtected")
            .header("content-type", "application/json")
            .body(Body::from(body.clone()))
            .unwrap();
        let missing_resp = app.clone().oneshot(missing_req).await.unwrap();
        assert_eq!(missing_resp.status(), StatusCode::UNAUTHORIZED);

        let valid_req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkProtected")
            .header("authorization", "Bearer dev-token")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let valid_resp = app.oneshot(valid_req).await.unwrap();
        assert_eq!(valid_resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_identity_returns_stored_document() {
        let app = test_app().await;
        let doc = make_signed_doc("amp:did:key:z6MkAlice");
        let body = serde_json::to_string(&doc).unwrap();

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkAlice")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let put_resp = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

        let get_req = Request::builder()
            .method("GET")
            .uri("/v1/identities/amp:did:key:z6MkAlice")
            .body(Body::empty())
            .unwrap();
        let get_resp = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = to_bytes(get_resp.into_body(), usize::MAX).await.unwrap();
        let returned: IdentityDocument = serde_json::from_slice(&body).unwrap();
        assert_eq!(returned.identity_id.0, "amp:did:key:z6MkAlice");
    }

    #[tokio::test]
    async fn get_unknown_identity_returns_404() {
        let app = test_app().await;
        let req = Request::builder()
            .method("GET")
            .uri("/v1/identities/amp:did:key:z6MkUnknown")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_alias_returns_identity_document_when_alias_matches() {
        let app = test_app().await;
        let doc = make_signed_doc_with_aliases(
            "amp:did:key:z6MkAliasTarget",
            vec!["alice@mesh".to_string()],
        );
        let body = serde_json::to_string(&doc).unwrap();

        let put_req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkAliasTarget")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let put_resp = app.clone().oneshot(put_req).await.unwrap();
        assert_eq!(put_resp.status(), StatusCode::NO_CONTENT);

        let get_req = Request::builder()
            .method("GET")
            .uri("/v1/aliases/alice@mesh")
            .body(Body::empty())
            .unwrap();
        let get_resp = app.oneshot(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_unsigned_identity_returns_400() {
        let app = test_app().await;
        let bundle = HybridPqKeyBundle::generate();
        let doc = IdentityDocument {
            version: 1,
            identity_id: IdentityId("amp:did:key:z6MkUnsigned".to_string()),
            aliases: vec![],
            signing_keys: vec![PublicKeyRecord {
                key_id: "sig-ed25519-1".to_string(),
                algorithm: ALG_ED25519.to_string(),
                public_key_b64: STANDARD.encode(bundle.ed25519_verifying_key_bytes),
            }],
            encryption_keys: vec![],
            supported_suites: vec![],
            relay_endpoints: vec![],
            signature: None, // unsigned
        };
        let body = serde_json::to_string(&doc).unwrap();
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkUnsigned")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(json["error"]["code"], "invalid_signature");
    }

    #[tokio::test]
    async fn put_identity_rejects_id_mismatch() {
        let app = test_app().await;
        let doc = make_signed_doc("amp:did:key:z6MkReal");
        let body = serde_json::to_string(&doc).unwrap();
        let req = Request::builder()
            .method("PUT")
            .uri("/v1/identities/amp:did:key:z6MkDifferent")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp_body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(json["error"]["code"], "identity_id_mismatch");
    }
}
