use std::sync::atomic::{AtomicU64, Ordering};

use lib::api::connection::{ClientRequestId, Message, MessageWire};
use tracing::{instrument, span, Instrument, Level};

use crate::connection_handler::{
    handle_authenticated_connection, handle_unauthenticated_connection,
};
use axum::{
    extract::{ws::Message as WsMessage, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};

pub static ACTIVE_WS_CONNECTIONS_COUNTER: AtomicU64 = AtomicU64::new(0);

/// HTTP request that we will upgrade into a `WebSocket` connection
pub async fn unauthenticated_ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws_handler(ws, false)
}

pub async fn authenticated_ws_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws_handler(ws, true)
}

#[instrument(skip(ws), name = "websocket")]
pub fn ws_handler(ws: WebSocketUpgrade, authenticated: bool) -> impl IntoResponse {
    // TODO: Logging, maybe filter out the user_agent
    // Internally this spawns a tokio task, so we're not
    // doing it ourselves
    ws.on_upgrade(move |socket| async move {
        ACTIVE_WS_CONNECTIONS_COUNTER.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            "Opened WS connection (Active: {})",
            ACTIVE_WS_CONNECTIONS_COUNTER.load(Ordering::Acquire)
        );

        // Convert Sink<WsMessage> into a Sink<MessageWire>.
        let socket = socket.with::<MessageWire, _, _, _>(|message_wire: MessageWire| async {
            Ok::<_, axum::Error>(WsMessage::Binary(message_wire.to_bytes()))
        });

        // Convert Stream<Item = Result<Option<WsMessage>, _> into Stream<Item = MessageWire>
        let socket = socket.map(|ws_m: Result<WsMessage, _>| match ws_m {
            Ok(WsMessage::Binary(bytes)) => Ok(MessageWire::from_bytes(&bytes).map_err(|_| ())?),
            Ok(WsMessage::Ping(bytes)) => {
                Ok(MessageWire(ClientRequestId::nil(), Message::Ping(bytes)))
            }
            Ok(WsMessage::Close(_)) => Ok(MessageWire(ClientRequestId::nil(), Message::Bye)),
            _ => Err(()),
        });

        let ws_span = span!(Level::INFO, "WS", auth = %authenticated);

        if authenticated {
            let socket = Box::pin(socket);

            handle_authenticated_connection(socket)
                .instrument(ws_span)
                .await;
        } else {
            handle_unauthenticated_connection(socket)
                .instrument(ws_span)
                .await;
        }

        // WS connection ended
        ACTIVE_WS_CONNECTIONS_COUNTER.fetch_sub(1, Ordering::Relaxed);
        tracing::info!(
            "Closed WS connection (Active: {})",
            ACTIVE_WS_CONNECTIONS_COUNTER.load(Ordering::Acquire)
        );
    })
}
