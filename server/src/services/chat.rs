use std::sync::LazyLock;

use lib::{
    api::{
        connection::{
            ChatServiceMessage::{self, MlsMessage, QueueDone, QueueEmpty},
            ListenerId, Message, ServiceError, ServiceResult, UnauthRequest,
        },
        group::{DeliveryStamp, SendMessageRequest},
    },
    crypto::blinded_address::{BlindedAddressPublic, BLINDED_ADDRESS_PUBLIC_LENGTH},
};
use scc::ebr::Guard;
use sled::Tree;
use tokio::{sync::broadcast, task::AbortHandle};
use tracing::Level;

use crate::{
    authenticator::verify_blinded_address,
    connection::{ConnectionService, RequestHandler},
    db::DB,
    error::Error,
};

pub type OutgoingMlsMessage = Vec<u8>;

/// Keep track of all the connections that are listening to a given blinded address.
/// When a new message is received by the server we send it through the broadcast.
static BROADCASTERS: LazyLock<
    scc::TreeIndex<BlindedAddressPublic, broadcast::Sender<(DeliveryStamp, OutgoingMlsMessage)>>,
> = LazyLock::new(scc::TreeIndex::default);

/// Keep track of the [`RequestId`] and their task abort handle. If a request
/// decides to stop listening, then we call the abort handle.
static LISTENERS: LazyLock<scc::HashMap<ListenerId, AbortHandle>> =
    LazyLock::new(scc::HashMap::default);

/// Add a connection into the listeners of a `BlindedAddress`.
pub async fn add_listener(
    blinded_address: BlindedAddressPublic,
    listener_id: ListenerId,
    mut request: impl RequestHandler,
) -> Result<(), ()> {
    let mut rx = BROADCASTERS
        .peek_with(&blinded_address, |_, tx| tx.subscribe())
        .unwrap_or({
            let (tx, rx) = broadcast::channel(128);
            let _ = BROADCASTERS.insert_async(blinded_address, tx).await;

            rx
        });

    let handle = tokio::task::spawn(async move {
        while let Ok((delivery_id, msg)) = rx.recv().await {
            request
                .message(Message::Unauth(UnauthRequest::ChatService(MlsMessage(
                    delivery_id,
                    msg,
                ))))
                .await
                // If ws is closed, task will simply panic and close
                .expect("Connection is open");
        }
    });

    if let Err((_, old_handler)) = LISTENERS
        .insert_async(listener_id, handle.abort_handle())
        .await
    {
        // Task already existed, abort old one.
        old_handler.abort();
    }

    Ok(())
}

#[derive(Default)]
pub struct ChatService;

impl ConnectionService<ChatServiceMessage> for ChatService {
    async fn handle_request(
        request: &mut impl RequestHandler,
        msg: ChatServiceMessage,
    ) -> Result<(), Error> {
        match msg {
            ChatServiceMessage::RetrieveQueue(req) => {
                let mut iter = ChatService::open_message_queue(&req.blinded_address)?
                    .range(req.server_delivery_id.as_bytes().as_slice()..);

                let mut counter = 0;

                while let Some(Ok((delivery_id_bytes, message_bytes))) = iter.next() {
                    let delivery_id = DeliveryStamp::try_from(&*delivery_id_bytes)
                        .map_err(|()| Error::UnknownError)?;

                    request
                        .message(Message::Unauth(UnauthRequest::ChatService(MlsMessage(
                            delivery_id,
                            message_bytes.to_vec(),
                        ))))
                        .await?;
                    counter += 1;
                }

                if counter > 0 {
                    request
                        .message(Message::Unauth(UnauthRequest::ChatService(QueueDone(
                            counter,
                        ))))
                        .await?;
                } else {
                    request
                        .message(Message::Unauth(UnauthRequest::ChatService(QueueEmpty)))
                        .await?;
                }

                Ok(())
            }
            ChatServiceMessage::SubscribeToAddress(listener_id, blinded_address) => {
                if add_listener(blinded_address, listener_id, request.clone())
                    .await
                    .is_ok()
                {
                    tracing::event!(
                        Level::INFO,
                        "User began listening to {}...",
                        blinded_address
                    );
                    request.message(Message::Ok).await?;
                } else {
                    request.error(ServiceError::InternalError).await?;
                }

                Ok(())
            }
            ChatServiceMessage::SendMessage(req) => {
                request
                    .map_service_result(ChatService::send_message, req)
                    .await
            }
            ChatServiceMessage::StopListening(req_id) => {
                Self::remove_listener_if_exists(&req_id);
                request.message(Message::Ok).await
            }
            _ => request.error(ServiceError::InvalidOperation).await,
        }
    }
}

impl ChatService {
    pub fn send_message(request: SendMessageRequest) -> ServiceResult {
        let (verified_blinded_address, verified_message) =
            verify_blinded_address(request.blinded_address_proof)
                .map_err(|_| ServiceError::InvalidCredentials)?;

        let queue_tree = Self::open_message_queue(&verified_blinded_address)
            .map_err(|_| ServiceError::InternalError)?;

        // DeliveryId is guaranteed to generate a unique database key
        let delivery_stamp = DeliveryStamp::generate();

        queue_tree
            .insert(delivery_stamp.as_bytes(), verified_message.clone())
            .map_err(Error::from)?;

        // Broadcast message to all the listeners
        tokio::spawn(async move {
            let guard = Guard::new();

            if let Some(broadcast) = BROADCASTERS.peek(&verified_blinded_address, &guard) {
                if let Ok(many) = broadcast.send((delivery_stamp, verified_message)) {
                    tracing::debug!(
                        "Broadcasting message to {} listener(s) at {}",
                        many,
                        &verified_blinded_address
                    );
                } else {
                    // TODO: What to do if broadcast is closed?
                    tracing::error!("Broadcasting message {delivery_stamp:?} failed.");
                }
            }
        });

        Ok(Message::Unauth(UnauthRequest::ChatService(
            ChatServiceMessage::Delivered(delivery_stamp),
        )))
    }

    #[inline]
    pub fn open_message_queue(blinded_address: &BlindedAddressPublic) -> Result<Tree, Error> {
        // "queue/" (6 bytes) + Blinded public length
        let mut bytes = [0u8; 6 + BLINDED_ADDRESS_PUBLIC_LENGTH];
        bytes[..6].copy_from_slice(b"queue/");
        bytes[6..].copy_from_slice(&blinded_address.0);
        Ok(DB.open_tree(bytes)?)
    }

    pub fn remove_listener_if_exists(listener_id: &ListenerId) {
        if let Some((_, join_handle)) = LISTENERS.remove(listener_id) {
            tracing::debug!("Removing Listener for {listener_id:?}");
            join_handle.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::{
        api::{
            connection::{ClientRequestId, MessageWire},
            group::GetMessagesRequest,
        },
        crypto::{blinded_address::BlindedAddressSecret, rng::random_bytes},
    };
    use tokio::sync::mpsc;
    use tracing::Span;

    use crate::connection::Request;

    use super::*;

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn test_chat_service() {
        let valid_proof = |msg: Vec<u8>| {
            let secret = random_bytes::<16>();
            let mut ba_secret = BlindedAddressSecret::from_group_secret(&secret);
            let ba_proof = ba_secret.create_proof(msg);

            ba_proof
        };

        let valid_blinded_proof = valid_proof(b"I remember you was conflicted".to_vec());

        let invalid_blinded_proof = {
            let mut tmp = valid_blinded_proof.clone();
            tmp.message = b"Misusing your influence".to_vec();

            tmp
        };

        // Send fake message fails
        assert_eq!(
            ChatService::send_message(SendMessageRequest {
                blinded_address_proof: invalid_blinded_proof
            }),
            Err(ServiceError::InvalidCredentials),
            "Sending a message with an invalid blinded address should not work"
        );

        // Send message A, B and C. Take note of a timestamp so we can retrieve B and C
        // while skipping A.

        let tree =
            ChatService::open_message_queue(&valid_blinded_proof.ba_public).expect("tree opens");

        assert!(tree.is_empty());

        // Send message A
        let a = vec![1, 2, 3];
        assert_eq!(
            ChatService::send_message(SendMessageRequest {
                blinded_address_proof: valid_proof(a.clone())
            }),
            Ok(Message::Ok),
            "Sending a message with a valid blinded address should work"
        );

        let stamp_a = DeliveryStamp::generate();

        // Send message B
        let b = vec![1, 2, 3, 4];

        assert_eq!(
            ChatService::send_message(SendMessageRequest {
                blinded_address_proof: valid_proof(b.clone())
            }),
            Ok(Message::Ok),
            "Sending a message with a valid blinded address should work"
        );

        let stamp_b = DeliveryStamp::generate();

        // Send message C
        let c = vec![1, 2, 3, 4, 5];
        assert_eq!(
            ChatService::send_message(SendMessageRequest {
                blinded_address_proof: valid_proof(c.clone())
            }),
            Ok(Message::Ok),
            "Sending a message with a valid blinded address should work"
        );

        // Did the server successfully store messages A, B, C in correct order?
        assert!(!tree.is_empty());
        let mut iter = tree.iter();
        assert_eq!(
            iter.next().expect("iter isn't empty").expect("i/o works").1,
            a.clone()
        );
        assert_eq!(
            iter.next().expect("iter isn't empty").expect("i/o works").1,
            b.clone()
        );
        assert_eq!(
            iter.next().expect("iter isn't empty").expect("i/o works").1,
            c.clone()
        );

        // Now, we want to retrieve all messages after B.

        let request = GetMessagesRequest {
            blinded_address: valid_blinded_proof.ba_public,
            server_delivery_id: stamp_a,
        };

        let (sender, mut receiver) = mpsc::unbounded_channel();
        let request_id = ClientRequestId::generate();
        let mut request_handler = Request::make(sender, request_id, &Span::none());

        ChatService::handle_request(
            &mut request_handler,
            ChatServiceMessage::RetrieveQueue(request),
        )
        .await
        .expect("request handler is valid");

        // We receive message B and C, but not A.

        match receiver.recv().await.expect("valid response") {
            MessageWire(
                recv_request_id,
                Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::MlsMessage(
                    recv_stamp,
                    recv,
                ))),
            ) => {
                assert_eq!(recv_request_id, request_id);
                assert!(recv_stamp > stamp_a);
                assert_eq!(recv, b);
            }
            other => {
                panic!("Unexpected response, got {other:?}");
            }
        };

        match receiver.recv().await.expect("valid response") {
            MessageWire(
                recv_request_id,
                Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::MlsMessage(
                    recv_stamp,
                    recv,
                ))),
            ) => {
                assert_eq!(recv_request_id, request_id);
                assert!(recv_stamp > stamp_a);
                assert_eq!(recv, c);
            }
            other => {
                panic!("Unexpected response, got {other:?}");
            }
        };

        match receiver.recv().await.expect("valid response") {
            MessageWire(
                recv_request_id,
                Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::QueueDone(2))),
            ) => {
                assert_eq!(recv_request_id, request_id);
            }
            other => {
                panic!("Unexpected response, got {other:?}");
            }
        };

        let request = GetMessagesRequest {
            blinded_address: valid_blinded_proof.ba_public,
            server_delivery_id: stamp_b,
        };

        let (sender, mut receiver) = mpsc::unbounded_channel();
        let request_id = ClientRequestId::generate();
        let mut request_handler = Request::make(sender, request_id, &Span::none());

        ChatService::handle_request(
            &mut request_handler,
            ChatServiceMessage::RetrieveQueue(request),
        )
        .await
        .expect("request handler is valid");

        // We receive message C, but not A and B.

        match receiver.recv().await.expect("valid response") {
            MessageWire(
                recv_request_id,
                Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::MlsMessage(
                    recv_stamp,
                    recv,
                ))),
            ) => {
                assert_eq!(recv_request_id, request_id);
                assert!(recv_stamp > stamp_b);
                assert_eq!(recv, c);
            }
            other => {
                panic!("Unexpected response, got {other:?}");
            }
        };

        match receiver.recv().await.expect("valid response") {
            MessageWire(
                recv_request_id,
                Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::QueueDone(1))),
            ) => {
                assert_eq!(recv_request_id, request_id);
            }
            other => {
                panic!("Unexpected response, got {other:?}");
            }
        };
    }
}
