mod api;
mod config;
mod storage;

use std::{net::SocketAddr, sync::Arc};

use axum::{routing::{get, post}, Router};
use config::RelayConfig;
use storage::FileEnvelopeStore;

#[tokio::main]
async fn main() {
    let config = RelayConfig::default();
    let store = Arc::new(FileEnvelopeStore::new(config.storage_dir.clone()));

    let app = Router::new()
        .route("/health", get(api::health))
        .route("/v1/envelopes", post({
            let store = Arc::clone(&store);
            move |payload| api::store_envelope(store, payload)
        }))
        .route("/v1/envelopes/:recipient_id", get({
            let store = Arc::clone(&store);
            move |path| api::fetch_envelopes(store, path)
        }));

    let addr: SocketAddr = config.bind.parse().expect("valid socket address");
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind relay listener");
    println!("relay listening on http://{}", addr);
    axum::serve(listener, app).await.expect("serve relay");
}
