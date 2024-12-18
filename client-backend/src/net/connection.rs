//! A generic connection handler using a stream.
use std::ops::Deref;

use jenga::{timeout::TimeoutError, Middleware};
use lib::{
    api::connection::{
        ChatServiceMessage, ListenerId, Message, MessageWire, UnauthRequest,
        MIN_REQUEST_TIMEOUT_SECS,
    },
    crypto::blinded_address::BlindedAddressPublic,
};
use tokio::sync::mpsc;

use crate::manager::listener::ListenerMessage;

use super::{raw_connection::RawConnection, RequestError};

const CONNECTION_RETRY_COUNT: usize = 1;

/// A struct encapsulating [`RawConnection`] (and derefs as one) used to
/// encapsulate jenga's `request` function with middlewares like timeout and retry.
pub struct Connection {
    inner: jenga::retry::Retry<
        CONNECTION_RETRY_COUNT,
        MessageWire,
        jenga::timeout::Timeout<MessageWire, RawConnection>,
    >,
}

/// The message enum used to request [`Connection`]'s.
#[derive(Debug, Clone)]
pub enum ConnectionServiceMessage {
    Request(MessageWire),
    Listen(
        ListenerId,
        BlindedAddressPublic,
        mpsc::Sender<ListenerMessage>,
    ),
}

impl From<MessageWire> for ConnectionServiceMessage {
    fn from(value: MessageWire) -> Self {
        Self::Request(value)
    }
}

impl jenga::Service<ConnectionServiceMessage> for Connection {
    type Response = Message;
    type Error = TimeoutError<RequestError>;

    async fn request(&self, msg: ConnectionServiceMessage) -> Result<Self::Response, Self::Error> {
        match msg {
            ConnectionServiceMessage::Request(message_wire) => {
                self.inner.request(message_wire).await
            }
            ConnectionServiceMessage::Listen(listener_id, blinded_address, tx) => {
                let message_wire: MessageWire = Message::Unauth(UnauthRequest::ChatService(
                    ChatServiceMessage::SubscribeToAddress(listener_id, blinded_address),
                ))
                .into();

                let request_id = message_wire.0;
                match self.inner.request(message_wire).await {
                    Ok(resp) => {
                        if let Message::Ok = resp {
                            let _ = self.listening.insert_async(request_id, tx).await;
                            Ok(Message::Ok)
                        } else {
                            Err(TimeoutError::ServiceError(RequestError::UnexpectedAnswer))
                        }
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }
}

impl From<RawConnection> for Connection {
    fn from(value: RawConnection) -> Self {
        let timeout = jenga::timeout::Timeout::new(value, MIN_REQUEST_TIMEOUT_SECS);
        let retry = jenga::retry::Retry::instant(timeout);
        Self { inner: retry }
    }
}

impl Deref for Connection {
    type Target = RawConnection;

    fn deref(&self) -> &Self::Target {
        self.inner.inner_service().inner_service()
    }
}
