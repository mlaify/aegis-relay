use std::sync::Arc;

use aegis_api_types::{
    EnvelopeLifecycleResponse, FetchEnvelopeResponse, RelayCleanupResponse, RelayError,
    RelayErrorResponse, StoreEnvelopeRequest, StoreEnvelopeResponse,
};
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::HeaderMap,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::storage::LifecycleOutcome;
use crate::AppState;

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn store_envelope(
    State(state): State<Arc<AppState>>,
    payload: Result<Json<StoreEnvelopeRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match payload {
        Ok(req) => req,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &err.body_text())
        }
    };

    if let Err(message) = validate_envelope(&req.envelope) {
        return error_response(StatusCode::BAD_REQUEST, "invalid_envelope", &message);
    }

    match state.store.store(&req.envelope).await {
        Ok(()) => Json(StoreEnvelopeResponse {
            accepted: true,
            relay_id: "local-relay".to_string(),
        })
        .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to store envelope",
        ),
    }
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
    if let Err(resp) = require_lifecycle_token(&state, &headers) {
        return resp;
    }
    match state.store.acknowledge(&recipient_id, &envelope_id).await {
        Ok(LifecycleOutcome::Acknowledged) => Json(EnvelopeLifecycleResponse {
            recipient_id,
            envelope_id,
            status: "acknowledged".to_string(),
        })
        .into_response(),
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
    if let Err(resp) = require_lifecycle_token(&state, &headers) {
        return resp;
    }
    match state.store.delete(&recipient_id, &envelope_id).await {
        Ok(LifecycleOutcome::Deleted) => Json(EnvelopeLifecycleResponse {
            recipient_id,
            envelope_id,
            status: "deleted".to_string(),
        })
        .into_response(),
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
    if let Err(resp) = require_lifecycle_token(&state, &headers) {
        return resp;
    }
    match state.store.cleanup().await {
        Ok(report) => Json(RelayCleanupResponse {
            expired_removed: report.expired_removed,
            orphan_ack_removed: report.orphan_ack_removed,
        })
        .into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to run cleanup",
        ),
    }
}

fn require_lifecycle_token(state: &AppState, headers: &HeaderMap) -> Result<(), Response> {
    let Some(required) = state.capability_token.as_deref() else {
        return Ok(());
    };

    let provided = token_from_headers(headers);
    match provided {
        Some(token) if token == required => Ok(()),
        Some(_) => Err(error_response(
            StatusCode::FORBIDDEN,
            "forbidden",
            "invalid relay capability token",
        )),
        None => Err(error_response(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "missing relay capability token",
        )),
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

    use crate::storage::FileStore;
    use crate::AppState;

    fn test_app(store_path: &str, token: Option<&str>) -> Router {
        let state = Arc::new(AppState {
            store: Arc::new(FileStore::new(store_path)),
            capability_token: token.map(|t| t.to_string()),
        });
        Router::new()
            .route("/healthz", get(super::healthz))
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
        let app = test_app("./data-test-routes-malformed", None);

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
        let app = test_app("./data-test-routes-empty", None);

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
        // `/dev/null` is a file, so trying to create a directory under it will fail.
        let app = test_app("/dev/null/aegis-relay-storage-fail", None);

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
        let app = test_app("./data-test-routes-invalid-envelope", None);

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
        let app = test_app("./data-test-routes-lifecycle", None);

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
        let app = test_app("./data-test-routes-lifecycle-token", Some("dev-token"));

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
        let app = test_app("./data-test-routes-lifecycle-open", None);

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
        let app = test_app("./data-test-routes-cleanup-token", Some("dev-token"));

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
}
