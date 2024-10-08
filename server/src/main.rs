use axum::{routing::get, Router};
use lib::api::server::Server;
use std::net::SocketAddr;
use tracing::Level;
use websocket::unauthenticated_ws_handler;

use crate::websocket::authenticated_ws_handler;

pub mod accounts;
pub mod authenticator;
pub mod connection;
pub mod connection_handler;
pub mod db;
pub mod error;
pub mod services;
pub mod websocket;

/// jemalloc is an allocator that is more efficient for the server.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise the logger
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .pretty()
        .init();

    tracing::info!("Hello world!");

    let server = Server::localhost();

    start(&server).await
}

pub async fn start(server: &Server) -> Result<(), Box<dyn std::error::Error>> {
    let app = Router::new()
        .route("/", get(unauthenticated_ws_handler))
        .route("/auth", get(authenticated_ws_handler));

    let listener = tokio::net::TcpListener::bind(server.url_unauth()).await?;

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
