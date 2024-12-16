use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

use super::connection::Connection;
use super::connection::RawConnection;
use super::Connector;
use super::ServerConnectionError;

#[derive(Debug, Default, Clone, Copy)]
/// [`Connection`] holds all the relevant information,
/// so we keep this struct empty
pub struct WebsocketConnector;

impl Connector for WebsocketConnector {}
impl jenga::Service<String> for WebsocketConnector {
    type Response = Connection;
    type Error = ServerConnectionError;

    async fn request(&self, msg: String) -> Result<Self::Response, Self::Error> {
        let url = msg;
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
