mod routes;
mod storage;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{delete, get, post},
    Router,
};
use storage::FileStore;

pub struct AppState {
    pub store: Arc<FileStore>,
    pub capability_token: Option<String>,
}

#[tokio::main]
async fn main() {
    let state = Arc::new(AppState {
        store: Arc::new(FileStore::new("./data")),
        capability_token: std::env::var("AEGIS_RELAY_CAPABILITY_TOKEN").ok(),
    });
    let app = Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/v1/envelopes", post(routes::store_envelope))
        .route("/v1/envelopes/:recipient_id", get(routes::fetch_envelopes))
        .route(
            "/v1/envelopes/:recipient_id/:envelope_id/ack",
            post(routes::acknowledge_envelope),
        )
        .route(
            "/v1/envelopes/:recipient_id/:envelope_id",
            delete(routes::delete_envelope),
        )
        .route("/v1/cleanup", post(routes::cleanup_store))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8787));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("aegis-relay listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
