use std::sync::Arc;

use aegis_api_types::{RelayError, RelayErrorResponse};
use aegis_proto::IdentityDocument;
use axum::{
    extract::{rejection::JsonRejection, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::AppState;

pub async fn put_identity(
    State(state): State<Arc<AppState>>,
    Path(identity_id): Path<String>,
    payload: Result<Json<IdentityDocument>, JsonRejection>,
) -> Response {
    let Json(doc) = match payload {
        Ok(doc) => doc,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RelayErrorResponse {
                    error: RelayError {
                        code: "invalid_request".to_string(),
                        message: err.body_text(),
                    },
                }),
            )
                .into_response()
        }
    };
    if doc.identity_id.0 != identity_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(RelayErrorResponse {
                error: RelayError {
                    code: "identity_id_mismatch".to_string(),
                    message: "identity_id in document must match URL path".to_string(),
                },
            }),
        )
            .into_response();
    }
    match state.store.store_identity(&doc).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RelayErrorResponse {
                error: RelayError {
                    code: "storage_error".to_string(),
                    message: "failed to store identity".to_string(),
                },
            }),
        )
            .into_response(),
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
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RelayErrorResponse {
                error: RelayError {
                    code: "storage_error".to_string(),
                    message: "failed to fetch identity".to_string(),
                },
            }),
        )
            .into_response(),
    }
}
