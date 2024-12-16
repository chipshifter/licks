//! A generic connection handler using a stream.
use std::{
    ops::Deref,
    sync::{Arc, Mutex, PoisonError},
    time::Duration,
};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use jenga::{timeout::TimeoutError, Middleware};
use lib::api::connection::{
    ChatServiceMessage, ClientRequestId, Message, MessageWire, UnauthRequest,
    MIN_REQUEST_TIMEOUT_SECS,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::sleep,
};

use tokio_util::sync::CancellationToken;

use crate::manager::{connections::RequestError, listener::ListenerMessage};

type RequestHashmap = Arc<scc::HashMap<ClientRequestId, oneshot::Sender<Message>>>;
type ListenerHashmap = Arc<scc::HashMap<ClientRequestId, mpsc::Sender<ListenerMessage>>>;

#[derive(Debug)]
pub struct RawConnection {
    pub request_sender: mpsc::Sender<Vec<u8>>,
    pub unattended: Mutex<mpsc::Receiver<Message>>,
    // We keep track of mpsc channels per-connection that are "listening" to incoming
    // messages. When the connection receives such a message, it gets send to the mpsc
    // sender.
    pub listening: ListenerHashmap,
    pub requests: RequestHashmap,
    pub cancellation_token: CancellationToken,
}

impl RawConnection {
    pub fn start<S: Stream<Item = Vec<u8>> + Sink<Vec<u8>> + Send + 'static + Unpin>(
        stream: S,
    ) -> Self {
        let (mut sender, mut receiver) = stream.split();
        let (tx, mut rx) = mpsc::channel(16);
        let (unattended_sender, unattended) = mpsc::channel::<Message>(16);
        let cancellation_token = CancellationToken::new();

        let cancellation_token_clone = cancellation_token.clone();

        let requests: RequestHashmap = scc::HashMap::new().into();
        let requests_clone: RequestHashmap = requests.clone();
        let listening: ListenerHashmap = scc::HashMap::new().into();
        let listening_clone = listening.clone();
        tokio::task::spawn(async move {
            loop {
                tokio::select! {
                    // Received a request from ConnectionManager,
                    // send it to the stream
                    Some(req) = rx.recv() => {
                        if sender.send(req).await.is_err() {
                            log::error!("Connection unexpectedly closed when trying to send request message");
                            rx.close();
                            return;
                        }
                    },
                    // Received a response from the connection
                    Some(bytes) = receiver.next() => {
                        if let Ok(msg) = MessageWire::from_bytes(&bytes) {
                            let request_id = msg.0;
                            if request_id.is_nil() {
                                // Not a heartbeat?
                                if !msg.1.eq(&Message::Pong(vec![72, 66])) {
                                    log::warn!("A message with no RequestId came around,but wasn't a heartbeat: {:?}", msg.1);
                                    let _ = unattended_sender.send(msg.1).await;
                                }
                            } else if let Some(tx) = listening_clone.get_async(&request_id).await {
                                log::debug!("Listening {request_id:?}: got new message. Sending to manager");
                                // if request got dropped, ignore result
                                match msg.1 {
                                    Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::MlsMessage(timestamp, msg_bytes))) => {
                                        let _ = tx.send((timestamp, msg_bytes)).await;
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
            unattended: Mutex::new(unattended),
            listening,
            requests,
            cancellation_token,
        }
    }

    /// Tell the connection that a given [`RequestId`] is used for listening to incoming messages.
    /// This sets the [`RequestId`] in a special state where instead of being used once, it can expect
    /// more than one message at any time.
    ///
    /// This should be called *before* sending a request to listen.
    pub async fn start_listen(
        &self,
        request_id: ClientRequestId,
        tx: mpsc::Sender<ListenerMessage>,
    ) {
        let _ = self.listening.insert_async(request_id, tx).await;
    }

    /// Tell the connection to stop listening for the given [`RequestId`]
    pub async fn stop_listen(&self, request_id: &ClientRequestId) {
        self.listening.remove_async(request_id).await;
    }

    pub fn is_open(&self) -> bool {
        !(self.cancellation_token.is_cancelled() || self.request_sender.is_closed())
    }

    pub fn close(&self) -> Vec<Message> {
        self.cancellation_token.cancel();
        Vec::new()
    }

    pub fn collect_unattended(&self) -> Vec<Message> {
        let mut vec: Vec<Message> = Vec::new();
        let mut lock = self
            .unattended
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Ok(message) = lock.try_recv() {
            vec.push(message);
        }

        vec
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

impl jenga::Service<MessageWire> for Connection {
    type Response = Message;
    type Error = TimeoutError<RequestError>;

    async fn request(&self, msg: MessageWire) -> Result<Self::Response, Self::Error> {
        self.inner.request(msg).await
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
