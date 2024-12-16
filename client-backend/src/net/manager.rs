use std::sync::Arc;

use jenga::{timeout::TimeoutError, Service};
use lib::api::{
    connection::{Message, MessageWire, UnauthRequest},
    server::Server,
};

use crate::manager::connections::RequestError;

use super::{connection::Connection, websocket::WebsocketConnector, ServerConnectionError};

/// Connection with jenga middlewares, notably Restart, which automatically restarts a connection
/// if a message fails to send.
type ConnectionJenga = jenga::restart::Restart<
    MessageWire,
    Message,
    TimeoutError<RequestError>,
    Connection,
    String,
    ServerConnectionError,
    WebsocketConnector,
>;

#[derive(Default, Clone)]
pub struct WebsocketManager {
    connector: WebsocketConnector,
    conns: Arc<scc::HashMap<String, ConnectionJenga>>,
}

impl WebsocketManager {
    pub fn new() -> Self {
        Self {
            connector: WebsocketConnector,
            conns: Arc::new(scc::HashMap::new()),
        }
    }

    pub async fn request_unauth(
        &self,
        server: &Server,
        msg: UnauthRequest,
    ) -> anyhow::Result<Message> {
        let url = server.ws_url_unauth();
        if let Some(conn) = self.conns.get_async(&url).await {
            Ok(conn
                .get()
                .request(MessageWire::from(Message::Unauth(msg)))
                .await?)
        } else {
            let ws = ConnectionJenga::new(self.connector, url.clone()).await?;

            let resp = ws.request(MessageWire::from(Message::Unauth(msg))).await;

            let _ = self.conns.insert_async(url, ws).await;

            Ok(resp?)
        }
    }
}
