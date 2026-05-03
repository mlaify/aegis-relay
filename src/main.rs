mod audit;
mod config;
mod identity_routes;
mod routes;
mod storage;

use std::{net::SocketAddr, sync::Arc};

use axum::{
    routing::{delete, get, post, put},
    Router,
};
use config::{RelayAuthConfig, RelayConfig, RetentionPolicy};
use storage::{SqliteStore, Store};

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub auth: RelayAuthConfig,
    pub retention: RetentionPolicy,
    pub audit: audit::AuditSink,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = RelayConfig::from_env();
    let store = SqliteStore::open(&cfg.db_path)
        .await
        .expect("failed to open SQLite store");

    let state = Arc::new(AppState {
        store: Arc::new(store),
        auth: cfg.auth.clone(),
        retention: cfg.retention.clone(),
        audit: audit::AuditSink::new(cfg.audit_log_path.clone()),
    });

    let app = Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/v1/status", get(routes::status))
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
        .route("/v1/aliases/:alias", get(identity_routes::get_alias))
        .with_state(state);

    let addr: SocketAddr = cfg.bind.parse().expect("invalid AEGIS_RELAY_BIND address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("aegis-relay listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
