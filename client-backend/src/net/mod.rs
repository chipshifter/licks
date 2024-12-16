use async_trait::async_trait;
use connection::Connection;

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

/// This trait starts a generic [`Connection`] socket. This is the layer where
/// diff connection technologies like WebSocket or WebTransport can be implemented.
#[async_trait]
pub trait ConnectionStarter {
    async fn start_connection(url: String) -> Result<Connection, ServerConnectionError>;
}
