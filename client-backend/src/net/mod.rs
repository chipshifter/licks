use connection::Connection;

pub mod connection;
pub mod manager;
pub mod raw_connection;
pub mod websocket;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ConnectionError {
    #[error("Could not open a connection")]
    CouldNotConnect,
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

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("Sending request failed because the connection closed")]
    SendConnectionClosed,
    #[error("Receiving request failed because the connection closed")]
    ReceiveConnectionClosed,
    #[error("The request timed out")]
    Timeout,
    #[error("The request gave an unexpected answer")]
    UnexpectedAnswer,
}

/// This trait starts a generic [`Connection`] socket. This is the layer where
/// diff connection technologies like WebSocket or WebTransport can be implemented.
pub trait Connector:
    jenga::Service<String, Response = Connection, Error = ConnectionError>
{
    #[allow(async_fn_in_trait)]
    async fn start_connection(&self, url: String) -> Result<Connection, ConnectionError> {
        self.request(url).await
    }
}
