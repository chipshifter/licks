use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use lib::{api::connection::MessageWire, crypto::noise::ServerHandshake};
use std::sync::Mutex;
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
        // Convert Sink<WsMessage> into a Sink<Vec<u8>>.
        let socket = socket.with::<Vec<u8>, _, _, _>(|bytes: Vec<u8>| async {
            Ok::<_, axum::Error>(WsMessage::Binary(bytes))
        });

        // Convert Stream<Item = Result<Option<WsMessage>, _> into Stream<Item = Vec<u8>>
        let socket = socket.map(|ws_m: Result<WsMessage, _>| match ws_m {
            Ok(WsMessage::Binary(bytes)) => Ok(bytes),
            _ => Err(()),
        });

        let mut socket = Box::pin(socket);

        let Some(Ok(client_handshake)) = socket.next().await else {
            let _ = socket.close().await;
            return;
        };

        let server_handshake = ServerHandshake::respond(&client_handshake).expect("todo");
        let Ok(()) = socket.send(server_handshake.buffer.read().to_vec()).await else {
            panic!();
        };

        let Some(Ok(client_response)) = socket.next().await else {
            let _ = socket.close().await;
            return;
        };

        let server_transport = Arc::new(Mutex::new(
            server_handshake
                .complete_handshake(&client_response)
                .expect("todo"),
        ));

        // Convert Sink<Vec<u8>> into a Sink<MessageWire>.
        let server_transport_with = server_transport.clone();
        let socket = socket.with::<MessageWire, _, _, _>(move |msg: MessageWire| {
            let server_transport_with = server_transport_with.clone();
            async move {
                let mut lock = server_transport_with.lock().expect("no poison");
                let enc = lock.write(&msg.to_bytes()).expect("todo");
                Ok::<_, axum::Error>(enc.to_vec())
            }
        });

        // Convert Stream<Item = Result<Option<Vec<u8>>, _> into Stream<Item = MessageWire>
        let server_transport_map = server_transport.clone();
        let socket = socket.map(move |ws_m: Result<Vec<u8>, _>| match ws_m {
            Ok(bytes) => {
                let mut lock = server_transport_map.lock().expect("no poison");
                let dec = lock.read(&bytes).map_err(|_| ())?;
                Ok(MessageWire::from_bytes(dec).map_err(|_| ())?)
            }
            _ => Err(()),
        });

        ACTIVE_WS_CONNECTIONS_COUNTER.fetch_add(1, Ordering::Relaxed);
        tracing::info!(
            "Opened WS connection (Active: {})",
            ACTIVE_WS_CONNECTIONS_COUNTER.load(Ordering::Acquire)
        );

        let ws_span = span!(Level::INFO, "WS Noise", auth = %authenticated);

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
