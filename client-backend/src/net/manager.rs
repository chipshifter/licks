use std::sync::Arc;

use jenga::{timeout::TimeoutError, Service};
use lib::api::{
    connection::{AuthRequest, Message, MessageWire, UnauthRequest},
    server::Server,
};

use crate::manager::{account::Profile, connections::RequestError};

use super::{connection::Connection, websocket::WebsocketConnector, ServerConnectionError};

/// Connection with jenga middlewares, notably Restart, which automatically restarts a connection
/// if a message fails to send.
type UnauthConnectionJenga = jenga::restart::Restart<
    MessageWire,
    Message,
    TimeoutError<RequestError>,
    Connection,
    String,
    ServerConnectionError,
    WebsocketConnector,
>;

type AuthConnectionJenga = jenga::restart::Restart<
    MessageWire,
    Message,
    TimeoutError<RequestError>,
    Connection,
    Arc<Profile>,
    ServerConnectionError,
    WebsocketConnector,
>;

#[derive(Default, Clone)]
pub struct WebsocketManager {
    connector: WebsocketConnector,
    unauth_conns: Arc<scc::HashMap<String, UnauthConnectionJenga>>,
    auth_conns: Arc<scc::HashMap<Arc<Profile>, AuthConnectionJenga>>,
}

impl WebsocketManager {
    pub fn new() -> Self {
        Self {
            connector: WebsocketConnector,
            unauth_conns: Arc::new(scc::HashMap::new()),
            auth_conns: Arc::new(scc::HashMap::new()),
        }
    }

    pub async fn request_unauth(
        &self,
        server: &Server,
        msg: UnauthRequest,
    ) -> anyhow::Result<Message> {
        let url = server.ws_url_unauth();
        if let Some(conn) = self.unauth_conns.get_async(&url).await {
            Ok(conn
                .get()
                .request(MessageWire::from(Message::Unauth(msg)))
                .await?)
        } else {
            let ws = UnauthConnectionJenga::new(self.connector, url.clone()).await?;

            let resp = ws.request(MessageWire::from(Message::Unauth(msg))).await;

            let _ = self.unauth_conns.insert_async(url, ws).await;

            Ok(resp?)
        }
    }

    pub async fn request_auth(
        &self,
        profile: Arc<Profile>,
        msg: AuthRequest,
    ) -> anyhow::Result<Message> {
        if let Some(conn) = self.auth_conns.get_async(&profile).await {
            Ok(conn
                .get()
                .request(MessageWire::from(Message::Auth(msg)))
                .await?)
        } else {
            let ws = AuthConnectionJenga::new(self.connector, profile.clone()).await?;

            let resp = ws.request(MessageWire::from(Message::Auth(msg))).await;

            let _ = self.auth_conns.insert_async(profile, ws).await;

            Ok(resp?)
        }
    }
}
