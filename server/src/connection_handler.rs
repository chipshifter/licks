//! This where connections and requests are handled.
//!
//! [`handle_connection_socket`] is the generic loop where the socket waits for incoming requests
//! and processes them when it receives them. It includes a timeout/heartbeat mechanism so
//! if the user stops responsing at all then their connection with close.
//!
//! It takes in a stream+sink of [`MessageWire`] though we'll probably split those in
//! the future.
//!
//! [`handle_unauthenticated_connection`] redirects straight to [`handle_unauthenticated_connection`]
//! with a request handler meant to handle unauthenticated requests only.
//!
//! [`handle_authenticated_connection`] first prompts the user to respond to a challenge
//! (to authenticate them), then also redirects to [`handle_connection_socket`] but with
//! an authenticated request handler.

use std::sync::Arc;

use futures_util::{SinkExt, Stream, StreamExt};
use lib::{
    api::messages::{Message, MessageWire, MAX_CONNECTION_TIMEOUT_SECS},
    crypto::challenge::AuthChallenge,
};
use tokio::{sync::mpsc, time::timeout};
use tracing::{event, Level};

use crate::{accounts::AccountService, connection::Request};

pub async fn handle_unauthenticated_connection<
    Socket: Stream<Item = Result<MessageWire, ()>> + SinkExt<MessageWire> + Send + 'static,
>(
    socket: Socket,
) where
    <Socket as futures_util::Sink<MessageWire>>::Error: std::marker::Send,
{
    let req_handler = |req: Request, msg: Message| {
        Request::handle(req, msg);
    };

    handle_connection_socket(socket, req_handler).await;
}

pub async fn handle_authenticated_connection<
    Socket: Stream<Item = Result<MessageWire, ()>> + SinkExt<MessageWire> + Send + Unpin + 'static,
>(
    mut socket: Socket,
) where
    <Socket as futures_util::Sink<MessageWire>>::Error: std::marker::Send,
{
    if let Ok(Some(chain)) = timeout(MAX_CONNECTION_TIMEOUT_SECS, async {
        // wait for client to ask for challenge.
        // if they ask for anything else, close conneciton.
        let Some(Ok(MessageWire(req_id, Message::GetChallenge))) = socket.next().await else {
            // client didn't ask for challenge. abort
            event!(Level::DEBUG, "The client did not ask for challenge.");
            let _ = socket.close().await;
            return None;
        };

        // send challenge to client. if it fails, return function.
        let our_challenge_bytes = AuthChallenge::generate();
        if socket
            .send(MessageWire(req_id, Message::Challenge(our_challenge_bytes)))
            .await
            .is_err()
        {
            event!(Level::DEBUG, "Could not send challenge to client.");
            return None;
        }

        // challenge is now sent.
        // wait we wait for the challenge response. if we get a message
        // that isn't the challenge response, we close the connection.
        if let Some(Ok(MessageWire(req_id, Message::ChallengeResponse(challenge_response)))) =
            socket.next().await
        {
            let Ok(verified_chain) = challenge_response.verify(our_challenge_bytes) else {
                // Chain self signatures failed.
                event!(Level::DEBUG, "The client's certificate chain was invalid.");
                let _ = socket.close().await;
                return None;
            };

            if AccountService::is_chain_valid(&verified_chain).unwrap_or(false) {
                event!(Level::INFO, "Authenticated connection handshake successful");
                let _ = socket.send(MessageWire(req_id, Message::Ok)).await;

                let authenticated_chain = Arc::new(verified_chain);

                return Some(authenticated_chain);
            }

            event!(Level::DEBUG, "The client's chain is unknown.");
            // The chain was not registered to the server.
            let _ = socket.close().await;
        }

        // We did not get the response we expected.
        let _ = socket.close().await;

        None
    })
    .await
    {
        let req_handler = move |req: Request, msg: Message| {
            Request::handle_authenticated(req, chain.clone(), msg);
        };

        handle_connection_socket(socket, req_handler).await;
    } else {
        event!(
            Level::DEBUG,
            "Authenticated connection challenged failed or timed out."
        );
    }
}

/// Handle any socket, authenticated or unauthenticated.
/// This is done with the use of a generic `FnOnce` which needs to be passed.
/// That function is what will handle the request.
/// For unauthenticated requests ([`handle_unauthenticated_connection`]), that's [`Request::handle`].
/// For authenticated requests ([`handle_authenticated_connection`]), that's [`Request::handle_authenticated`].
pub async fn handle_connection_socket<
    Socket: Stream<Item = Result<MessageWire, ()>> + SinkExt<MessageWire> + Send + 'static,
>(
    socket: Socket,
    req_handler: impl Fn(Request, Message) + Send + 'static,
) where
    <Socket as futures_util::Sink<MessageWire>>::Error: std::marker::Send,
{
    let (mut sender, mut receiver) = socket.split();

    let span = tracing::Span::current();

    // create an mpsc receiver. the senders will be cloned and sent to each request the user is making.
    // the receiver will just loop and send back whatever to the socket
    let (req_sender, mut req_receiver) = mpsc::unbounded_channel::<MessageWire>();
    loop {
        tokio::select! {
            // client requested something, we handle it
            Some(Ok(msg)) = receiver.next() => {
                req_handler(Request::make(req_sender.clone(), msg.0, &span), msg.1);
            },
            // we finished handling a request. we try to
            // send it back to the client
            Some(stuff) = req_receiver.recv()  => {
                if stuff.1 == Message::Bye || sender.send(stuff).await.is_err() {
                    event!(Level::DEBUG, "Connection closed by user");
                    break;
                };
            },
            // if nothing happened in the connection
            // for X seconds then we shut it down
            () = tokio::time::sleep(MAX_CONNECTION_TIMEOUT_SECS) => {
                event!(Level::DEBUG, "Connection timed out");
                break;
            },
            // this should never happen because sleep()
            // should always complete, but just in case
            else => {
                event!(Level::DEBUG, "Closing connection");
                break;
            }
        };
    }
}
