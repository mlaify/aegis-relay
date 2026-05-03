mod identity_routes;
mod routes;
mod storage;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use storage::{SqliteStore, Store};

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub capability_token: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let db_path = std::env::var("AEGIS_DB_PATH").unwrap_or_else(|_| "aegis-relay.db".to_string());
    let store = SqliteStore::open(&db_path)
        .await
        .expect("failed to open SQLite store");

    let state = Arc::new(AppState {
        store: Arc::new(store),
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
        .route(
            "/v1/identities/:identity_id",
            get(identity_routes::get_identity),
        )
        .route(
            "/v1/identities/:identity_id",
            put(identity_routes::put_identity),
        )
        .with_state(state);

    let bind = std::env::var("AEGIS_RELAY_BIND").unwrap_or_else(|_| "0.0.0.0:8787".to_string());
    let addr: SocketAddr = bind.parse().expect("invalid AEGIS_RELAY_BIND address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("aegis-relay listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
