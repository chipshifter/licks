//! A generic connection handler using a stream.
use std::{fmt::Debug, ops::Deref};

use jenga::{timeout::TimeoutError, Middleware};
use lib::{
    api::messages::{
        ChatServiceMessage, ListenerId, Message, MessageWire, UnauthRequest,
        MIN_REQUEST_TIMEOUT_SECS,
    },
    crypto::{blinded_address::BlindedAddressPublic, listener::ListenerToken},
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

impl Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("RawConnection", self.deref())
            .finish()
    }
}

#[cfg(test)]
impl PartialEq for Connection {
    fn eq(&self, other: &Self) -> bool {
        self.connection_id == other.connection_id
    }
}

/// The message enum used to request [`Connection`]'s.
#[derive(Debug, Clone)]
pub enum ConnectionServiceMessage {
    Request(MessageWire),
    Listen(BlindedAddressPublic, mpsc::Sender<ListenerMessage>),
    StopListen(ListenerId),
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
        if !self.is_open() {
            // If we already know the connection closed, instantly error out rather than
            // wait for inevitable timeout
            return Err(TimeoutError::ServiceError(
                RequestError::SendConnectionClosed,
            ));
        }

        match msg {
            ConnectionServiceMessage::Request(message_wire) => {
                self.inner.request(message_wire).await
            }
            ConnectionServiceMessage::Listen(blinded_address, tx) => {
                let listener_token = ListenerToken::default();

                let message_wire: MessageWire = Message::Unauth(UnauthRequest::ChatService(
                    ChatServiceMessage::SubscribeToAddress(
                        listener_token.commitment(),
                        blinded_address,
                    ),
                ))
                .into();

                let request_id = message_wire.0;
                match self.inner.request(message_wire).await {
                    Ok(resp) => {
                        if let Message::Unauth(UnauthRequest::ChatService(
                            ChatServiceMessage::ListenStarted(listener_id),
                        )) = resp
                        {
                            let _ = self
                                .listener_ids
                                .insert_async(listener_id, request_id)
                                .await;

                            let _ = self
                                .listening
                                .insert_async(request_id, (tx, listener_token))
                                .await;
                            Ok(resp)
                        } else {
                            Err(TimeoutError::ServiceError(RequestError::UnexpectedAnswer))
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            ConnectionServiceMessage::StopListen(listener_id) => {
                let Some((_, request_id)) = self.listener_ids.remove_async(&listener_id).await
                else {
                    // No listener found internally, we assume there was nothing to begin with and return Ok
                    return Ok(Message::Ok);
                };

                let Some((_, entry)) = self.listening.remove_async(&request_id).await else {
                    // Same as above
                    return Ok(Message::Ok);
                };

                // This will close when dropped
                let _tx = entry.0;
                let listener_token = entry.1;

                let message_wire: MessageWire = Message::Unauth(UnauthRequest::ChatService(
                    ChatServiceMessage::StopListening(listener_id, listener_token),
                ))
                .into();

                self.inner.request(message_wire).await
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
