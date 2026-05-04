mod admin_routes;
mod audit;
mod config;
mod identity_routes;
mod prekey_routes;
mod routes;
mod storage;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    http::{HeaderName, Method},
    routing::{delete, get, post, put},
    Router,
};
use config::{RelayConfig, RuntimeConfig};
use storage::{SqliteStore, Store};
use tower_http::cors::{Any, CorsLayer};

pub struct AppState {
    pub store: Arc<dyn Store>,
    pub runtime: Arc<std::sync::RwLock<RuntimeConfig>>,
    pub admin_token: Option<String>,
    pub audit: audit::AuditSink,
    pub runtime_config_path: PathBuf,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let cfg = RelayConfig::from_env();
    let store = SqliteStore::open(&cfg.db_path)
        .await
        .expect("failed to open SQLite store");

    let runtime_config_path = cfg.runtime_config_path.clone();
    let admin_token = cfg.admin_token.clone();
    let audit_log_path = cfg.audit_log_path.clone();
    let bind = cfg.bind.clone();
    let runtime = cfg.into_shared_runtime();

    let state = Arc::new(AppState {
        store: Arc::new(store),
        runtime,
        admin_token,
        audit: audit::AuditSink::new(audit_log_path),
        runtime_config_path,
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
        .route(
            "/v1/identities/:identity_id/prekeys",
            post(prekey_routes::publish_prekeys),
        )
        .route(
            "/v1/identities/:identity_id/prekey",
            get(prekey_routes::claim_prekey),
        )
        // Admin routes — all protected by AEGIS_RELAY_ADMIN_TOKEN
        .route("/admin/status", get(admin_routes::admin_status))
        .route(
            "/admin/config",
            get(admin_routes::admin_get_config).put(admin_routes::admin_put_config),
        )
        .route(
            "/admin/tokens",
            get(admin_routes::admin_list_tokens).post(admin_routes::admin_add_token),
        )
        .route(
            "/admin/tokens/:index",
            delete(admin_routes::admin_revoke_token),
        )
        .route("/admin/cleanup", post(admin_routes::admin_cleanup))
        .route("/admin/identities", get(admin_routes::admin_list_identities))
        .route("/admin/audit", get(admin_routes::admin_audit_log))
        .with_state(state)
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE])
                .allow_headers([
                    HeaderName::from_static("authorization"),
                    HeaderName::from_static("content-type"),
                    HeaderName::from_static("x-aegis-admin-token"),
                ]),
        );

    let addr: SocketAddr = bind.parse().expect("invalid AEGIS_RELAY_BIND address");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("aegis-relay listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
