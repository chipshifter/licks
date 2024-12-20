//! A generic connection handler using a stream.
use std::{sync::Arc, time::Duration};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use lib::{
    api::messages::{
        ChatServiceMessage, ClientRequestId, ListenerId, Message, MessageWire, UnauthRequest,
    },
    crypto::{listener::ListenerToken, noise::ClientHandshake},
};
use tokio::{
    sync::{mpsc, oneshot},
    time::sleep,
};

use tokio_util::sync::CancellationToken;

use crate::manager::listener::ListenerMessage;

use super::RequestError;

type RequestHashmap = Arc<scc::HashMap<ClientRequestId, oneshot::Sender<Message>>>;
type ListenerHashmap =
    Arc<scc::HashMap<ClientRequestId, (mpsc::Sender<ListenerMessage>, ListenerToken)>>;
type ListenerIdsHashmap = Arc<scc::HashMap<ListenerId, ClientRequestId>>;

#[derive(Debug)]
/// A low-level "raw" connection, that just handles bytes in, bytes out.
/// This struct is not aware of what method is used to connect or
/// to what server it is connected.
pub struct RawConnection {
    pub request_sender: mpsc::Sender<Vec<u8>>,
    pub listener_ids: ListenerIdsHashmap,
    pub listening: ListenerHashmap,
    pub requests: RequestHashmap,
    pub cancellation_token: CancellationToken,
}

impl RawConnection {
    pub fn start<S: Stream<Item = Vec<u8>> + Sink<Vec<u8>> + Send + 'static + Unpin>(
        stream: S,
    ) -> Self {
        let (mut sender, mut receiver) = stream.split();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(16);

        let cancellation_token = CancellationToken::new();
        let cancellation_token_clone = cancellation_token.clone();

        let requests: RequestHashmap = scc::HashMap::new().into();
        let requests_clone: RequestHashmap = requests.clone();

        let listening: ListenerHashmap = scc::HashMap::new().into();
        let listening_clone = listening.clone();

        tokio::task::spawn(async move {
            // Encryption is done at the connection level, not at the request level,
            // so it should be handled here

            // Start encryption
            let handshake = ClientHandshake::prepare_handshake().expect("todo");

            if let Err(_) = sender.send(handshake.buffer.read().to_vec()).await {
                panic!();
            }

            // Wait for server response
            let server_response = receiver
                .next()
                .await
                .expect("Server responds to Noise handshake");

            let (mut transport, buffer) = handshake
                .complete_handshake(&server_response)
                .expect("Noise handshake succeeds");

            // Send our final payload to server
            if let Err(_) = sender.send(buffer.read().to_vec()).await {
                panic!();
            }

            loop {
                tokio::select! {
                    // Received a request from ConnectionManager,
                    // send it to the stream
                    Some(unencrypted_req) = rx.recv() => {
                        // Encrypt before sending
                        let Ok(encrypted_request) = transport.write(&unencrypted_req) else {
                            rx.close();
                            return;
                        };

                        if sender.send(encrypted_request.to_vec()).await.is_err() {
                            log::error!("Connection unexpectedly closed when trying to send request message");
                            rx.close();
                            return;
                        }
                    },
                    // Received a response from the connection
                    Some(bytes) = receiver.next() => {
                        let Ok(decrypted_bytes) = transport.read(&bytes) else {
                            rx.close();
                            return;
                        };

                        if let Ok(msg) = MessageWire::from_bytes(decrypted_bytes) {
                            let request_id = msg.0;
                            if request_id.is_nil() {
                                // Not a heartbeat?
                                if !msg.1.eq(&Message::Pong(vec![72, 66])) {
                                    log::warn!("A message with no RequestId came around, but wasn't a heartbeat: {:?}", msg.1);
                                }
                            } else if let Some(entry) = listening_clone.get_async(&request_id).await {
                                log::debug!("Listening {request_id:?}: got new message. Sending to manager");
                                // if request got dropped, ignore result
                                match msg.1 {
                                    Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::MlsMessage(timestamp, msg_bytes))) => {
                                        let _ = entry.0.send((timestamp, msg_bytes)).await;
                                    },
                                    Message::Ok => {
                                        // All good, send Ok to complete request
                                        if let Some((_, tx)) = requests_clone.remove_async(&request_id).await {
                                            log::debug!("Received response for request {request_id:?}. Sending back to manager");
                                            // if request got dropped, ignore result
                                            let _ = tx.send(Message::Ok);
                                        }
                                    },
                                    _ => {
                                        log::error!("RequestId {request_id:?} was listening but received an unexpected message. Closing");
                                        listening_clone.remove_async(&request_id).await;
                                    }
                                }
                            } else if let Some((_, tx)) = requests_clone.remove_async(&request_id).await {
                                log::debug!("Received response for request {request_id:?}. Sending back to manager");
                                // if request got dropped, ignore result
                                let _ = tx.send(msg.1);
                            }
                        } else {
                            log::error!("Received a message but couldn't process it");
                        }
                    },
                    // If nothing happens for 15 seconds (meaning the other futures in the
                    // tokio::select didn't get chosen), we send a heartbeat ping to let
                    // the server know we're still alive and kicking
                    () = sleep(Duration::from_secs(15)) => {
                        log::debug!("Nothing happened on connection for 10 seconds, sending heartbeat");
                        if sender.send(MessageWire(ClientRequestId::generate(), Message::Ping(vec![72, 66])).to_bytes()).await.is_err() {
                            log::warn!("Connection channel sender errored out, so we're closing it.");
                            return;
                        }
                    }
                    () = cancellation_token_clone.cancelled() => {
                        return;
                    },
                    else => {
                        return;
                    }
                }
            }
        });

        Self {
            request_sender: tx,
            listening,
            listener_ids: scc::HashMap::new().into(),
            requests,
            cancellation_token,
        }
    }

    pub fn is_open(&self) -> bool {
        !(self.cancellation_token.is_cancelled() || self.request_sender.is_closed())
    }
}

impl Drop for RawConnection {
    fn drop(&mut self) {
        self.cancellation_token.cancel();
    }
}

impl jenga::Service<MessageWire> for RawConnection {
    type Response = Message;
    type Error = RequestError;

    /// Tries to send a message to the mpsc channel.
    /// Returns Err if the connection/stream went down
    async fn request(&self, wire: MessageWire) -> Result<Self::Response, Self::Error> {
        let (tx, rx) = oneshot::channel::<Message>();
        let request_id = wire.0;
        let _ = self.requests.insert_async(request_id, tx).await;

        self.request_sender
            .send(wire.to_bytes())
            .await
            .map_err(|_| {
                log::info!(
                    "Connection: Tried sending request {request_id:?} but connection was down"
                );

                RequestError::SendConnectionClosed
            })?;

        let Ok(resp) = rx.await else {
            return Err(RequestError::ReceiveConnectionClosed);
        };

        Ok(resp)
    }
}
