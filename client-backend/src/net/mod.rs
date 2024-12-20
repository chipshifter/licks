use std::sync::Arc;

use connection::{Connection, ConnectionServiceMessage};
use jenga::timeout::TimeoutError;
use lib::api::messages::Message;

use crate::manager::account::Profile;

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

// Connection + jenga middlewares, notably Restart, which automatically restarts a connection
// if a message fails to send.

type UnauthConnectionJenga<Connector> = jenga::restart::Restart<
    ConnectionServiceMessage,
    Message,
    TimeoutError<RequestError>,
    Connection,
    String,
    ConnectionError,
    Connector,
>;

type AuthConnectionJenga<Connector> = jenga::restart::Restart<
    ConnectionServiceMessage,
    Message,
    TimeoutError<RequestError>,
    Connection,
    Arc<Profile>,
    ConnectionError,
    Connector,
>;
