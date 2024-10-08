//! A generic trait/implementation of a bi-directional long lived connection.
//! This is mainly `WebSockets`, but may implement other things such as RPC or `WebTransport` etc.
use std::sync::Arc;

use async_trait::async_trait;
use connection::Connection;
use lib::api::{
    connection::{ClientRequestId, Message, MAX_CONNECTION_TIMEOUT_SECS},
    server::Server,
};
use tokio::time::timeout;

pub mod connection;
pub mod websocket;

use crate::manager::account::Profile;

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

/// A generic connection to a server
#[async_trait]
pub trait ServerConnection: Send + Sync {
    /// Opens an unauthenticated connection.
    async fn open_unauthenticated(server: &Server) -> Result<Self, ServerConnectionError>
    where
        Self: Sized;

    /// Opens an authenticated connection. It automatically passes the challenge
    /// using the credential secrets in `Profile`.
    async fn open_authenticated(profile: &Profile) -> Result<Self, ServerConnectionError>
    where
        Self: Sized;

    /// Close the connection completely.
    /// Returns the unattended messages that weren't collected
    /// if there are any.
    fn close(&self) -> Vec<Message>;
    fn is_open(&self) -> bool;

    /// A server request with no timeout.
    /// Warning: this can get stuck forever if the server doesn't respond
    /// to the request. You probably want to use `request` instead which has
    /// timeout built in.
    async fn request_no_timeout(
        &self,
        message: Message,
    ) -> Result<Vec<Message>, ServerConnectionError>;
    /// A server request with timeout.
    /// times out after [`constants::REQUEST_TIMEOUT_SECS`] seconds.
    async fn request(&self, message: Message) -> Result<Vec<Message>, ServerConnectionError> {
        match timeout(
            MAX_CONNECTION_TIMEOUT_SECS,
            self.request_no_timeout(message),
        )
        .await
        {
            Ok(resp) => resp,
            Err(_) => Err(ServerConnectionError::Timeout),
        }
    }
    /// Collects the messages that have been received but that do not have any
    /// request ID associated to them.
    fn collect_unattended(&self) -> Vec<Message>;
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
