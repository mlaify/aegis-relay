use std::sync::Arc;

use aegis_api_types::{
    FetchEnvelopeResponse, RelayError, RelayErrorResponse, StoreEnvelopeRequest,
    StoreEnvelopeResponse,
};
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::storage::FileStore;

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn store_envelope(
    State(store): State<Arc<FileStore>>,
    payload: Result<Json<StoreEnvelopeRequest>, JsonRejection>,
) -> Response {
    let Json(req) = match payload {
        Ok(req) => req,
        Err(err) => {
            return error_response(StatusCode::BAD_REQUEST, "invalid_request", &err.body_text())
        }
    };

    match store.store(&req.envelope).await {
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

pub async fn fetch_envelopes(
    State(store): State<Arc<FileStore>>,
    Path(recipient_id): Path<String>,
) -> Response {
    match store.fetch(&recipient_id).await {
        Ok(envelopes) => Json(FetchEnvelopeResponse { envelopes }).into_response(),
        Err(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage_error",
            "failed to fetch envelopes",
        ),
    }
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
        routing::{get, post},
        Router,
    };
    use tower::util::ServiceExt;

    use crate::storage::FileStore;

    fn test_app(store_path: &str) -> Router {
        let store = Arc::new(FileStore::new(store_path));
        Router::new()
            .route("/healthz", get(super::healthz))
            .route("/v1/envelopes", post(super::store_envelope))
            .route("/v1/envelopes/:recipient_id", get(super::fetch_envelopes))
            .with_state(store)
    }

    #[tokio::test]
    async fn store_envelope_returns_structured_bad_request_for_malformed_json() {
        let app = test_app("./data-test-routes-malformed");

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
        let app = test_app("./data-test-routes-empty");

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
        let app = test_app("/dev/null/aegis-relay-storage-fail");

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
}
