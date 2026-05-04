use std::sync::Arc;

use aegis_api_types::{
    EnvelopeLifecycleResponse, FetchEnvelopeResponse, RelayCleanupResponse, RelayError,
    RelayErrorResponse, RelayStatusResponse, StoreEnvelopeRequest, StoreEnvelopeResponse,
};
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::storage::{LifecycleOutcome, StoreOutcome};
use crate::{audit::AuditEvent, config::AuthMode, AppState};

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn status(State(state): State<Arc<AppState>>) -> Response {
    match state.store.metrics().await {
        Ok(m) => Json(RelayStatusResponse {
            envelopes_total: m.envelopes_total,
            envelopes_acknowledged: m.envelopes_acknowledged,
            envelopes_active: m.envelopes_active,
            identities_total: m.identities_total,
            auth_mode: match state.auth.mode {
                AuthMode::Open => "open".to_string(),
                AuthMode::Token => "token".to_string(),
            },
            require_token_for_push: state.auth.require_token_for_push,
            require_token_for_identity_put: state.auth.require_token_for_identity_put,
        })
        .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to fetch relay status",
        ),
    }
}

pub async fn store_envelope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    payload: Result<Json<StoreEnvelopeRequest>, JsonRejection>,
) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::PushEnvelope) {
        return err.into_response();
    }

    let Json(req) = match payload {
        Ok(req) => req,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &err.body_text())
        }
    };

    if let Err(message) = validate_envelope(&req.envelope) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_envelope", &message);
    }

    match state
        .store
        .store_with_prekey_consumption(&req.envelope)
        .await
    {
        Ok(StoreOutcome::Stored) => {
            let recipient_id = req.envelope.recipient_id.0.clone();
            let envelope_id = req.envelope.envelope_id.0.to_string();
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "store_envelope",
                    outcome: "ok",
                    recipient_id: Some(&recipient_id),
                    envelope_id: Some(&envelope_id),
                    identity_id: None,
                    detail: None,
                })
                .await;
            for key_id in &req.envelope.used_prekey_ids {
                state
                    .audit
                    .record(AuditEvent {
                        at: chrono::Utc::now(),
                        operation: "consume_prekey",
                        outcome: "ok",
                        recipient_id: Some(&recipient_id),
                        envelope_id: Some(&envelope_id),
                        identity_id: None,
                        detail: Some(key_id),
                    })
                    .await;
            }
            Json(StoreEnvelopeResponse {
                accepted: true,
                relay_id: "local-relay".to_string(),
            })
            .into_response()
        }
        Ok(StoreOutcome::PrekeyAlreadyUsed { key_id }) => {
            let recipient_id = req.envelope.recipient_id.0.clone();
            let envelope_id = req.envelope.envelope_id.0.to_string();
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "consume_prekey",
                    outcome: "conflict",
                    recipient_id: Some(&recipient_id),
                    envelope_id: Some(&envelope_id),
                    identity_id: None,
                    detail: Some(&key_id),
                })
                .await;
            error_response(
                StatusCode::CONFLICT,
                "prekey_already_used",
                &format!("prekey key_id {key_id} already consumed for recipient"),
            )
        }
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to store envelope",
        ),
    }
}

fn first_duplicate(ids: &[String]) -> Option<&str> {
    let mut seen = std::collections::HashSet::with_capacity(ids.len());
    for id in ids {
        if !seen.insert(id.as_str()) {
            return Some(id.as_str());
        }
    }
    None
}

fn validate_envelope(envelope: &aegis_proto::Envelope) -> Result<(), String> {
    if envelope.version != 1 {
        return Err("unsupported envelope version".to_string());
    }

    if envelope.content_type.trim().is_empty() {
        return Err("content_type must be non-empty".to_string());
    }

    if !envelope.content_type.starts_with("message/private") {
        return Err("content_type must start with message/private".to_string());
    }

    if envelope.recipient_id.0.trim().is_empty() {
        return Err("recipient_id must be non-empty".to_string());
    }

    if envelope.payload.nonce_b64.trim().is_empty() {
        return Err("payload.nonce_b64 must be non-empty".to_string());
    }

    if envelope.payload.ciphertext_b64.trim().is_empty() {
        return Err("payload.ciphertext_b64 must be non-empty".to_string());
    }

    // RFC-0003 §12: each key_id in used_prekey_ids must be unique.
    if let Some(dup) = first_duplicate(&envelope.used_prekey_ids) {
        return Err(format!("used_prekey_ids contains duplicate key_id {dup}"));
    }
    for key_id in &envelope.used_prekey_ids {
        if key_id.trim().is_empty() {
            return Err("used_prekey_ids entries must be non-empty".to_string());
        }
    }

    // Hybrid PQ suite requires KEM transport fields and a PQ signature.
    if envelope.suite_id == aegis_proto::SuiteId::HybridX25519MlKem768Ed25519MlDsa65 {
        if envelope
            .payload
            .eph_x25519_public_key_b64
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err(
                "payload.eph_x25519_public_key_b64 required for hybrid PQ suite".to_string(),
            );
        }
        if envelope
            .payload
            .mlkem_ciphertext_b64
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err("payload.mlkem_ciphertext_b64 required for hybrid PQ suite".to_string());
        }
        if envelope
            .outer_pq_signature_b64
            .as_ref()
            .map(|s| s.trim().is_empty())
            .unwrap_or(true)
        {
            return Err("outer_pq_signature_b64 required for hybrid PQ suite".to_string());
        }
    }

    Ok(())
}

pub async fn fetch_envelopes(
    State(state): State<Arc<AppState>>,
    Path(recipient_id): Path<String>,
) -> Response {
    match state.store.fetch(&recipient_id).await {
        Ok(envelopes) => Json(FetchEnvelopeResponse { envelopes }).into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to fetch envelopes",
        ),
    }
}

pub async fn acknowledge_envelope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((recipient_id, envelope_id)): Path<(String, String)>,
) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::LifecycleChange) {
        return err.into_response();
    }
    match state.store.acknowledge(&recipient_id, &envelope_id).await {
        Ok(LifecycleOutcome::Acknowledged) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "acknowledge_envelope",
                    outcome: "ok",
                    recipient_id: Some(&recipient_id),
                    envelope_id: Some(&envelope_id),
                    identity_id: None,
                    detail: None,
                })
                .await;
            Json(EnvelopeLifecycleResponse {
                recipient_id,
                envelope_id,
                status: "acknowledged".to_string(),
            })
            .into_response()
        }
        Ok(LifecycleOutcome::NotFound) => {
            error_response(StatusCode::NOT_FOUND, "not_found", "envelope not found")
        }
        Ok(LifecycleOutcome::Deleted) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "unexpected lifecycle outcome",
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to acknowledge envelope",
        ),
    }
}

pub async fn delete_envelope(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path((recipient_id, envelope_id)): Path<(String, String)>,
) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::LifecycleChange) {
        return err.into_response();
    }
    match state.store.delete(&recipient_id, &envelope_id).await {
        Ok(LifecycleOutcome::Deleted) => {
            state
                .audit
                .record(AuditEvent {
                    at: chrono::Utc::now(),
                    operation: "delete_envelope",
                    outcome: "ok",
                    recipient_id: Some(&recipient_id),
                    envelope_id: Some(&envelope_id),
                    identity_id: None,
                    detail: None,
                })
                .await;
            Json(EnvelopeLifecycleResponse {
                recipient_id,
                envelope_id,
                status: "deleted".to_string(),
            })
            .into_response()
        }
        Ok(LifecycleOutcome::NotFound) => {
            error_response(StatusCode::NOT_FOUND, "not_found", "envelope not found")
        }
        Ok(LifecycleOutcome::Acknowledged) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "unexpected lifecycle outcome",
        ),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to delete envelope",
        ),
    }
}

pub async fn cleanup_store(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Err(err) = require_auth(&state, &headers, AuthScope::LifecycleChange) {
        return err.into_response();
    }
    match state.store.cleanup(&state.retention).await {
        Ok(report) => Json(RelayCleanupResponse {
            expired_removed: report.expired_removed,
            orphan_ack_removed: report.orphan_ack_removed,
            old_removed: report.old_removed,
        })
        .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to run cleanup",
        ),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthScope {
    PushEnvelope,
    IdentityWrite,
    LifecycleChange,
}

pub fn require_auth(
    state: &AppState,
    headers: &HeaderMap,
    scope: AuthScope,
) -> Result<(), LifecycleAuthError> {
    if state.auth.mode == AuthMode::Open {
        return Ok(());
    }

    if scope == AuthScope::PushEnvelope && !state.auth.require_token_for_push {
        return Ok(());
    }
    if scope == AuthScope::IdentityWrite && !state.auth.require_token_for_identity_put {
        return Ok(());
    }

    let provided = token_from_headers(headers);
    if provided.is_none() {
        return Err(LifecycleAuthError::Unauthorized);
    }
    let provided = provided.unwrap();

    if state.auth.tokens.iter().any(|t| t == &provided) {
        Ok(())
    } else {
        Err(LifecycleAuthError::Forbidden)
    }
}

pub enum LifecycleAuthError {
    Unauthorized,
    Forbidden,
}

impl LifecycleAuthError {
    pub fn into_response(self) -> Response {
        match self {
            Self::Unauthorized => error_response(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "missing relay capability token",
            ),
            Self::Forbidden => error_response(
                StatusCode::FORBIDDEN,
                "forbidden",
                "invalid relay capability token",
            ),
        }
    }
}

fn token_from_headers(headers: &HeaderMap) -> Option<String> {
    if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
        if let Some(token) = value.strip_prefix("Bearer ") {
            let token = token.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    headers
        .get("x-aegis-relay-token")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
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

    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
        routing::{delete, get, post},
        Router,
    };
    use tower::util::ServiceExt;

    use crate::AppState;
    use crate::{
        audit::AuditSink,
        config::{AuthMode, RelayAuthConfig, RetentionPolicy},
        storage::SqliteStore,
    };

    async fn test_app(token: Option<&str>) -> Router {
        test_app_with_config(token, false).await
    }

    async fn test_app_with_config(token: Option<&str>, require_token_for_push: bool) -> Router {
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
                require_token_for_push,
                require_token_for_identity_put: true,
            },
            retention: RetentionPolicy {
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            },
            audit: AuditSink::new(None),
        });
        Router::new()
            .route("/healthz", get(super::healthz))
            .route("/v1/status", get(super::status))
            .route("/v1/envelopes", post(super::store_envelope))
            .route("/v1/envelopes/:recipient_id", get(super::fetch_envelopes))
            .route(
                "/v1/envelopes/:recipient_id/:envelope_id/ack",
                post(super::acknowledge_envelope),
            )
            .route(
                "/v1/envelopes/:recipient_id/:envelope_id",
                delete(super::delete_envelope),
            )
            .route("/v1/cleanup", post(super::cleanup_store))
            .with_state(state)
    }

    #[tokio::test]
    async fn store_envelope_returns_structured_bad_request_for_malformed_json() {
        let app = test_app(None).await;

        let req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from("{not-json"))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"]["code"], "invalid_request");
    }

    #[tokio::test]
    async fn fetch_envelopes_returns_empty_list_for_missing_recipient() {
        let app = test_app(None).await;

        let req = Request::builder()
            .method("GET")
            .uri("/v1/envelopes/amp:did:key:z6MkMissing")
            .body(Body::empty())
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["envelopes"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn store_envelope_returns_structured_storage_error_on_write_failure() {
        // Use FileStore with an impossible path to force a storage error.
        use crate::storage::FileStore;
        let store = FileStore::new("/dev/null/aegis-relay-storage-fail");
        let state = Arc::new(AppState {
            store: Arc::new(store),
            auth: RelayAuthConfig {
                mode: AuthMode::Open,
                tokens: vec![],
                require_token_for_push: false,
                require_token_for_identity_put: true,
            },
            retention: RetentionPolicy {
                purge_acknowledged_on_cleanup: true,
                max_message_age_days: None,
            },
            audit: AuditSink::new(None),
        });
        let app = Router::new()
            .route("/v1/envelopes", post(super::store_envelope))
            .with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{
                  "envelope": {
                    "version": 1,
                    "envelope_id": "550e8400-e29b-41d4-a716-446655440000",
                    "recipient_id": "amp:did:key:z6MkRecipient",
                    "sender_hint": null,
                    "created_at": "2026-01-02T03:04:05Z",
                    "expires_at": null,
                    "content_type": "message/private",
                    "suite_id": "DemoXChaCha20Poly1305",
                    "used_prekey_ids": [],
                    "payload": {
                      "nonce_b64": "bm9uY2U=",
                      "ciphertext_b64": "Y2lwaGVydGV4dA=="
                    },
                    "outer_signature_b64": null
                  }
                }"#,
            ))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"]["code"], "storage_error");
        assert_eq!(json["error"]["message"], "failed to store envelope");
    }

    #[tokio::test]
    async fn store_envelope_rejects_structurally_invalid_envelope() {
        let app = test_app(None).await;

        let req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{
                  "envelope": {
                    "version": 2,
                    "envelope_id": "550e8400-e29b-41d4-a716-446655440000",
                    "recipient_id": "",
                    "sender_hint": null,
                    "created_at": "2026-01-02T03:04:05Z",
                    "expires_at": null,
                    "content_type": "message/plain",
                    "suite_id": "DemoXChaCha20Poly1305",
                    "used_prekey_ids": [],
                    "payload": {
                      "nonce_b64": "",
                      "ciphertext_b64": ""
                    },
                    "outer_signature_b64": null
                  }
                }"#,
            ))
            .expect("request");

        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["error"]["code"], "invalid_envelope");
    }

    #[tokio::test]
    async fn acknowledge_and_delete_endpoints_return_lifecycle_responses() {
        let app = test_app(None).await;

        let envelope_json = r#"{
          "envelope": {
            "version": 1,
            "envelope_id": "550e8400-e29b-41d4-a716-446655440000",
            "recipient_id": "amp:did:key:z6MkRecipient",
            "sender_hint": null,
            "created_at": "2026-01-02T03:04:05Z",
            "expires_at": null,
            "content_type": "message/private",
            "suite_id": "DemoXChaCha20Poly1305",
            "used_prekey_ids": [],
            "payload": {
              "nonce_b64": "bm9uY2U=",
              "ciphertext_b64": "Y2lwaGVydGV4dA=="
            },
            "outer_signature_b64": null
          }
        }"#;

        let store_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_json))
            .expect("request");
        let store_resp = app
            .clone()
            .oneshot(store_req)
            .await
            .expect("store response");
        assert_eq!(store_resp.status(), StatusCode::OK);

        let ack_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440000/ack")
            .body(Body::empty())
            .expect("ack request");
        let ack_resp = app.clone().oneshot(ack_req).await.expect("ack response");
        assert_eq!(ack_resp.status(), StatusCode::OK);
        let ack_body = to_bytes(ack_resp.into_body(), usize::MAX)
            .await
            .expect("ack body");
        let ack_json: serde_json::Value = serde_json::from_slice(&ack_body).expect("ack json");
        assert_eq!(ack_json["status"], "acknowledged");

        let del_req = Request::builder()
            .method("DELETE")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440000")
            .body(Body::empty())
            .expect("delete request");
        let del_resp = app.oneshot(del_req).await.expect("delete response");
        assert_eq!(del_resp.status(), StatusCode::OK);
        let del_body = to_bytes(del_resp.into_body(), usize::MAX)
            .await
            .expect("delete body");
        let del_json: serde_json::Value = serde_json::from_slice(&del_body).expect("delete json");
        assert_eq!(del_json["status"], "deleted");
    }

    #[tokio::test]
    async fn lifecycle_routes_require_token_when_configured() {
        let app = test_app(Some("dev-token")).await;

        let envelope_json = r#"{
          "envelope": {
            "version": 1,
            "envelope_id": "550e8400-e29b-41d4-a716-446655440000",
            "recipient_id": "amp:did:key:z6MkRecipient",
            "sender_hint": null,
            "created_at": "2026-01-02T03:04:05Z",
            "expires_at": null,
            "content_type": "message/private",
            "suite_id": "DemoXChaCha20Poly1305",
            "used_prekey_ids": [],
            "payload": {
              "nonce_b64": "bm9uY2U=",
              "ciphertext_b64": "Y2lwaGVydGV4dA=="
            },
            "outer_signature_b64": null
          }
        }"#;

        let store_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_json))
            .expect("store request");
        let store_resp = app
            .clone()
            .oneshot(store_req)
            .await
            .expect("store response");
        assert_eq!(store_resp.status(), StatusCode::OK);

        let missing_token_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440000/ack")
            .body(Body::empty())
            .expect("ack request");
        let missing_token_resp = app
            .clone()
            .oneshot(missing_token_req)
            .await
            .expect("ack response");
        assert_eq!(missing_token_resp.status(), StatusCode::UNAUTHORIZED);

        let bad_token_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440000/ack")
            .header("authorization", "Bearer wrong-token")
            .body(Body::empty())
            .expect("ack request");
        let bad_token_resp = app
            .clone()
            .oneshot(bad_token_req)
            .await
            .expect("ack response");
        assert_eq!(bad_token_resp.status(), StatusCode::FORBIDDEN);

        let valid_token_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440000/ack")
            .header("authorization", "Bearer dev-token")
            .body(Body::empty())
            .expect("ack request");
        let valid_token_resp = app.oneshot(valid_token_req).await.expect("ack response");
        assert_eq!(valid_token_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn lifecycle_routes_remain_open_without_configured_token() {
        let app = test_app(None).await;

        let envelope_json = r#"{
          "envelope": {
            "version": 1,
            "envelope_id": "550e8400-e29b-41d4-a716-446655440001",
            "recipient_id": "amp:did:key:z6MkRecipient",
            "sender_hint": null,
            "created_at": "2026-01-02T03:04:05Z",
            "expires_at": null,
            "content_type": "message/private",
            "suite_id": "DemoXChaCha20Poly1305",
            "used_prekey_ids": [],
            "payload": {
              "nonce_b64": "bm9uY2U=",
              "ciphertext_b64": "Y2lwaGVydGV4dA=="
            },
            "outer_signature_b64": null
          }
        }"#;

        let store_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_json))
            .expect("store request");
        let _ = app
            .clone()
            .oneshot(store_req)
            .await
            .expect("store response");

        let ack_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes/amp:did:key:z6MkRecipient/550e8400-e29b-41d4-a716-446655440001/ack")
            .body(Body::empty())
            .expect("ack request");
        let ack_resp = app.oneshot(ack_req).await.expect("ack response");
        assert_eq!(ack_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn cleanup_route_requires_token_when_configured() {
        let app = test_app(Some("dev-token")).await;

        let missing_token_req = Request::builder()
            .method("POST")
            .uri("/v1/cleanup")
            .body(Body::empty())
            .expect("cleanup request");
        let missing_token_resp = app
            .clone()
            .oneshot(missing_token_req)
            .await
            .expect("cleanup response");
        assert_eq!(missing_token_resp.status(), StatusCode::UNAUTHORIZED);

        let valid_token_req = Request::builder()
            .method("POST")
            .uri("/v1/cleanup")
            .header("authorization", "Bearer dev-token")
            .body(Body::empty())
            .expect("cleanup request");
        let valid_token_resp = app
            .oneshot(valid_token_req)
            .await
            .expect("cleanup response");
        assert_eq!(valid_token_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn push_route_requires_token_when_configured_and_enabled() {
        let app = test_app_with_config(Some("dev-token"), true).await;

        let envelope_json = r#"{
          "envelope": {
            "version": 1,
            "envelope_id": "550e8400-e29b-41d4-a716-446655440010",
            "recipient_id": "amp:did:key:z6MkRecipient",
            "sender_hint": null,
            "created_at": "2026-01-02T03:04:05Z",
            "expires_at": null,
            "content_type": "message/private",
            "suite_id": "DemoXChaCha20Poly1305",
            "used_prekey_ids": [],
            "payload": {
              "nonce_b64": "bm9uY2U=",
              "ciphertext_b64": "Y2lwaGVydGV4dA=="
            },
            "outer_signature_b64": null
          }
        }"#;

        let missing_token_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_json))
            .expect("push request");
        let missing_token_resp = app
            .clone()
            .oneshot(missing_token_req)
            .await
            .expect("push response");
        assert_eq!(missing_token_resp.status(), StatusCode::UNAUTHORIZED);

        let valid_token_req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("authorization", "Bearer dev-token")
            .header("content-type", "application/json")
            .body(Body::from(envelope_json))
            .expect("push request");
        let valid_token_resp = app.oneshot(valid_token_req).await.expect("push response");
        assert_eq!(valid_token_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn status_returns_metrics() {
        let app = test_app(None).await;

        let req = Request::builder()
            .method("GET")
            .uri("/v1/status")
            .body(Body::empty())
            .expect("status request");
        let resp = app.oneshot(req).await.expect("status response");
        assert_eq!(resp.status(), StatusCode::OK);

        let body = to_bytes(resp.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json body");
        assert_eq!(json["auth_mode"], "open");
        assert!(json["envelopes_total"].is_number());
    }

    // -----------------------------------------------------------------------
    // Prekey enforcement route tests (RFC-0003 §12, RFC-0004 §5/§17)
    // -----------------------------------------------------------------------

    fn envelope_with_prekey_json(envelope_id: &str, prekey_ids: &[&str]) -> String {
        let ids_json = serde_json::to_string(prekey_ids).expect("ids");
        format!(
            r#"{{
              "envelope": {{
                "version": 1,
                "envelope_id": "{envelope_id}",
                "recipient_id": "amp:did:key:z6MkPkRoute",
                "sender_hint": null,
                "created_at": "2026-05-04T10:00:00Z",
                "expires_at": null,
                "content_type": "message/private",
                "suite_id": "DemoXChaCha20Poly1305",
                "used_prekey_ids": {ids_json},
                "payload": {{
                  "nonce_b64": "bm9uY2U=",
                  "ciphertext_b64": "Y2lwaGVydGV4dA=="
                }},
                "outer_signature_b64": null
              }}
            }}"#
        )
    }

    #[tokio::test]
    async fn store_envelope_with_prekey_succeeds_first_time() {
        let app = test_app(None).await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_with_prekey_json(
                "11111111-1111-1111-1111-111111111111",
                &["pk-route-1"],
            )))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn store_envelope_replaying_prekey_returns_409_prekey_already_used() {
        let app = test_app(None).await;

        // First envelope claims pk-route-replay -- accepted.
        let first = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_with_prekey_json(
                "22222222-2222-2222-2222-222222222222",
                &["pk-route-replay"],
            )))
            .expect("first");
        let first_resp = app.clone().oneshot(first).await.expect("first response");
        assert_eq!(first_resp.status(), StatusCode::OK);

        // Second envelope reuses the same prekey id -- rejected with 409.
        let second = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_with_prekey_json(
                "33333333-3333-3333-3333-333333333333",
                &["pk-route-replay"],
            )))
            .expect("second");
        let second_resp = app.oneshot(second).await.expect("second response");
        assert_eq!(second_resp.status(), StatusCode::CONFLICT);

        let body = to_bytes(second_resp.into_body(), usize::MAX)
            .await
            .expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "prekey_already_used");
        assert!(
            json["error"]["message"]
                .as_str()
                .unwrap_or_default()
                .contains("pk-route-replay"),
            "error message must identify the offending key_id, got: {}",
            json["error"]["message"]
        );
    }

    #[tokio::test]
    async fn store_envelope_with_duplicate_prekey_ids_returns_400() {
        let app = test_app(None).await;
        let req = Request::builder()
            .method("POST")
            .uri("/v1/envelopes")
            .header("content-type", "application/json")
            .body(Body::from(envelope_with_prekey_json(
                "44444444-4444-4444-4444-444444444444",
                &["pk-dup", "pk-dup"],
            )))
            .expect("request");
        let resp = app.oneshot(req).await.expect("response");
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let body = to_bytes(resp.into_body(), usize::MAX).await.expect("body");
        let json: serde_json::Value = serde_json::from_slice(&body).expect("json");
        assert_eq!(json["error"]["code"], "invalid_envelope");
    }
}
