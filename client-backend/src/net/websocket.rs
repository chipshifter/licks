use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

use super::connection::Connection;
use super::connection::RawConnection;
use super::ConnectionStarter;
use super::ServerConnectionError;

#[derive(Debug)]
/// [`Connection`] holds all the relevant information,
/// so we keep this struct empty
pub struct WebsocketConnection;

#[async_trait::async_trait]
impl ConnectionStarter for WebsocketConnection {
    async fn start_connection(url: String) -> Result<Connection, ServerConnectionError> {
        let (ws_stream, _) = connect_async(url).await.map_err(|e| {
            log::error!("Couldn't open WebSocket connection: {e:?}");
            ServerConnectionError::OpenFailed
        })?;

        let stream = ws_stream.with(|bytes| async {
            Ok::<_, tokio_tungstenite::tungstenite::Error>(TungsteniteMessage::Binary(bytes))
        });

        let stream = stream.filter_map(|msg| async {
            if let Ok(TungsteniteMessage::Binary(bytes)) = msg {
                Some(bytes)
            } else {
                None
            }
        });

        Ok(RawConnection::start(Box::pin(stream)).into())
    }
}
