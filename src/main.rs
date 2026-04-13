mod routes;
mod storage;

use std::{net::SocketAddr, sync::Arc};

use axum::{routing::{get, post}, Router};
use storage::FileStore;

#[tokio::main]
async fn main() {
    let store = Arc::new(FileStore::new("./data"));
    let app = Router::new()
        .route("/healthz", get(routes::healthz))
        .route("/v1/envelopes", post(routes::store_envelope))
        .route("/v1/envelopes/:recipient_id", get(routes::fetch_envelopes))
        .with_state(store);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8787));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    println!("aegis-relay listening on http://{}", addr);
    axum::serve(listener, app).await.unwrap();
}
