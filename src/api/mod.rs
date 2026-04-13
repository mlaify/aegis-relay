use std::sync::Arc;

use aegis_api_types::{FetchEnvelopeResponse, StoreEnvelopeRequest, StoreEnvelopeResponse};
use axum::{extract::{Json, Path}, http::StatusCode};

use crate::storage::FileEnvelopeStore;

pub async fn health() -> &'static str {
    "ok"
}

pub async fn store_envelope(
    store: Arc<FileEnvelopeStore>,
    Json(request): Json<StoreEnvelopeRequest>,
) -> Result<Json<StoreEnvelopeResponse>, (StatusCode, String)> {
    store
        .put(&request.envelope)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(StoreEnvelopeResponse {
        accepted: true,
        relay_id: request.envelope.envelope_id.0.to_string(),
    }))
}

pub async fn fetch_envelopes(
    store: Arc<FileEnvelopeStore>,
    Path(recipient_id): Path<String>,
) -> Result<Json<FetchEnvelopeResponse>, (StatusCode, String)> {
    let envelopes = store
        .get_for_recipient(&recipient_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(FetchEnvelopeResponse { envelopes }))
}
