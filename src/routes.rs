use std::sync::Arc;

use aegis_api_types::{FetchEnvelopeResponse, StoreEnvelopeRequest, StoreEnvelopeResponse};
use axum::{extract::{Path, State}, Json};

use crate::storage::FileStore;

pub async fn healthz() -> &'static str {
    "ok"
}

pub async fn store_envelope(
    State(store): State<Arc<FileStore>>,
    Json(req): Json<StoreEnvelopeRequest>,
) -> Json<StoreEnvelopeResponse> {
    store.store(&req.envelope).await.expect("store envelope");
    Json(StoreEnvelopeResponse {
        accepted: true,
        relay_id: "local-relay".to_string(),
    })
}

pub async fn fetch_envelopes(
    State(store): State<Arc<FileStore>>,
    Path(recipient_id): Path<String>,
) -> Json<FetchEnvelopeResponse> {
    let envelopes = store.fetch(&recipient_id).await.expect("fetch envelopes");
    Json(FetchEnvelopeResponse { envelopes })
}
