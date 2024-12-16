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

/// A global HashMap that keeps track of all pending requests. It is handled
/// by [`super::manager::connections::ConnectionManager`], but also used inside
/// individual [`Connection`] instances when they receive something to find which
/// oneshot channel to send back the request response to.
pub type PendingRequestSenders =
    scc::HashMap<ClientRequestId, tokio::sync::oneshot::Sender<Message>>;

/// This trait starts a generic [`Connection`] socket. This is the layer where
/// diff connection technologies like WebSocket or WebTransport can be implemented.
#[async_trait]
pub trait ConnectionStarter {
    async fn start_connection(url: String) -> Result<Connection, ServerConnectionError>;
}
