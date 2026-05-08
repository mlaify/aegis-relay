mod admin_routes;
mod audit;
mod config;
mod discovery;
mod federation;
mod identity_routes;
mod prekey_routes;
mod prometheus;
mod relay_identity;
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
    pub public_url: Option<String>,
    /// The relay's own hybrid signing identity (#32). Loaded once at
    /// startup and used to sign delivery receipts on inbound POSTs.
    /// Wrapped in `Arc` so the federation handler can clone the
    /// `AppState` cheaply across spawned tasks.
    pub relay_identity: Arc<storage::RelayIdentity>,
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
    let public_url = cfg.public_url.clone();
    let runtime = cfg.into_shared_runtime();

    // Phase 6 (#32): load or generate the relay's own signing identity.
    // The identity is small (a few KB of JSON) and cached for the
    // process lifetime — re-reading it from SQLite on every receipt
    // would be wasteful. Generation is one-shot per fresh database;
    // every subsequent boot loads the same persisted identity so
    // peers' cached signing keys stay valid across relay restarts.
    let store_arc: Arc<dyn Store> = Arc::new(store);
    let relay_identity = match store_arc
        .load_relay_identity()
        .await
        .expect("query relay_identity")
    {
        Some(existing) => {
            tracing::info!(
                identity_id = %existing.identity_id,
                "loaded existing relay identity from storage"
            );
            existing
        }
        None => {
            tracing::info!("no relay identity on disk; generating a fresh one");
            let fresh = relay_identity::generate()
                .expect("generate relay identity");
            store_arc
                .save_relay_identity(&fresh)
                .await
                .expect("persist relay identity");
            tracing::info!(
                identity_id = %fresh.identity_id,
                "generated + persisted relay identity"
            );
            fresh
        }
    };

    let state = Arc::new(AppState {
        store: store_arc,
        runtime,
        admin_token,
        audit: audit::AuditSink::new(audit_log_path),
        runtime_config_path,
        public_url,
        relay_identity: Arc::new(relay_identity),
    });

    // Phase 5 (#28): start the federation delivery worker. Off by default
    // when no public_url is configured — without one the worker can't
    // tell "us" from "them" and could loop. When public_url IS set, the
    // worker drains `outbound_deliveries` continuously in the background.
    if state.public_url.is_some() {
        let _handle = federation::spawn_delivery_worker(state.clone());
        tracing::info!("federation delivery worker started");
    } else {
        tracing::info!(
            "AEGIS_RELAY_PUBLIC_URL is unset; federation disabled (set it to enable push delivery)"
        );
    }

    let app = Router::new()
        .route(
            "/.well-known/aegis-config",
            get(discovery::well_known_aegis_config),
        )
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
        .route(
            "/admin/federation/metrics",
            get(admin_routes::admin_federation_metrics),
        )
        .route(
            "/admin/domains",
            get(admin_routes::admin_list_domains).post(admin_routes::admin_claim_domain),
        )
        .route(
            "/admin/domains/:domain/verify",
            post(admin_routes::admin_verify_domain),
        )
        .route(
            "/admin/domains/:domain",
            delete(admin_routes::admin_release_domain),
        )
        .route(
            "/admin/users",
            get(admin_routes::admin_list_users).post(admin_routes::admin_provision_user),
        )
        .route(
            "/admin/users/:alias",
            delete(admin_routes::admin_deprovision_user),
        );

    // Optional Prometheus exposition (#31). Off by default — operators
    // opt in with `AEGIS_PROMETHEUS_ENABLED=true`. When disabled the
    // route isn't registered, so `GET /metrics` returns axum's standard
    // 404 (a deliberate "endpoint missing" signal vs an empty body).
    let app = if prometheus::is_enabled() {
        tracing::info!("Prometheus metrics enabled at /metrics (no auth)");
        app.route("/metrics", get(prometheus::metrics_handler))
    } else {
        app
    };

    let app = app
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
