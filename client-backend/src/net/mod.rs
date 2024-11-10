//! A generic trait/implementation of a bi-directional long lived connection.
//! This is mainly `WebSockets`, but may implement other things such as RPC or `WebTransport` etc.
use std::sync::Arc;

use async_trait::async_trait;
use connection::Connection;
use lib::api::connection::{ClientRequestId, Message};

pub mod connection;
pub mod websocket;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ServerConnectionError {
    #[error("Could not open connection")]
    OpenFailed,
    #[error("The connection is closed")]
    IsClosed,
    #[error("Could not send request")]
    SendError,
    #[error("The request timed out")]
    Timeout,
    #[error("The authentication challange failed")]
    AuthChallengeFailed,
    #[error("This server URL is invalid")]
    InvalidServerUrl,
}

pub type PendingRequestSenders =
    Arc<scc::HashMap<ClientRequestId, tokio::sync::oneshot::Sender<Message>>>;

#[async_trait]
pub trait ConnectionStarter {
    async fn start_connection(
        url: String,
        pending_senders: PendingRequestSenders,
    ) -> Result<Connection, ServerConnectionError>;
}
