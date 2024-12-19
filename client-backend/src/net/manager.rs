use std::sync::Arc;

use jenga::Service;
use lib::{
    api::{
        connection::{AuthRequest, ListenerId, Message, MessageWire, UnauthRequest},
        server::Server,
    },
    crypto::blinded_address::BlindedAddressPublic,
};
use tokio::sync::mpsc;

use crate::manager::{account::Profile, listener::ListenerMessage};

use super::{
    connection::ConnectionServiceMessage, websocket::WebsocketConnector, AuthConnectionJenga,
    UnauthConnectionJenga,
};

#[derive(Default)]
pub struct WebsocketManager {
    connector: WebsocketConnector,
    unauth_conns: Arc<scc::HashMap<Server, UnauthConnectionJenga<WebsocketConnector>>>,
    auth_conns: Arc<scc::HashMap<Arc<Profile>, AuthConnectionJenga<WebsocketConnector>>>,
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
        let msg = MessageWire::from(Message::Unauth(msg)).into();
        if let Some(conn) = self.unauth_conns.get_async(server).await {
            Ok(conn.get().request(msg).await?)
        } else {
            let ws = UnauthConnectionJenga::new(self.connector, server.ws_url_unauth()).await?;
            let resp = ws.request(msg).await;
            let _ = self.unauth_conns.insert_async(server.clone(), ws).await;

            Ok(resp?)
        }
    }

    pub async fn request_auth(
        &self,
        profile: Arc<Profile>,
        msg: AuthRequest,
    ) -> anyhow::Result<Message> {
        let msg = MessageWire::from(Message::Auth(msg)).into();
        if let Some(conn) = self.auth_conns.get_async(&profile).await {
            Ok(conn.get().request(msg).await?)
        } else {
            let ws = AuthConnectionJenga::new(self.connector, profile.clone()).await?;
            let resp = ws.request(msg).await;
            let _ = self.auth_conns.insert_async(profile, ws).await;

            Ok(resp?)
        }
    }

    pub async fn start_listen(
        &self,
        server: &Server,
        blinded_address: BlindedAddressPublic,
        listener_tx: mpsc::Sender<ListenerMessage>,
    ) -> anyhow::Result<ListenerId> {
        let listener_id = ListenerId::generate();
        let msg = ConnectionServiceMessage::Listen(listener_id, blinded_address, listener_tx);

        if let Some(conn) = self.unauth_conns.get_async(server).await {
            let _ = conn.get().request(msg).await?;
        } else {
            let ws = UnauthConnectionJenga::new(self.connector, url.clone()).await?;
            let resp = ws.request(msg).await;
            let _ = self.unauth_conns.insert_async(server.clone(), ws).await;
            let _ = resp?;
        }

        Ok(listener_id)
    }

    pub async fn stop_listen(&self, server: &Server, listen_id: ListenerId) {
        todo!();
    }
}
