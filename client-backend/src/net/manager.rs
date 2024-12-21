use std::sync::Arc;

use anyhow::bail;
use jenga::Service;
use lib::{
    api::{
        messages::{
            AuthRequest, ChatServiceMessage, ListenerId, Message, MessageWire, UnauthRequest,
        },
        server::Server,
    },
    crypto::blinded_address::BlindedAddressPublic,
};
use tokio::sync::mpsc;

use crate::manager::{account::Profile, listener::ListenerMessage};

use super::{
    connection::ConnectionServiceMessage, AuthConnectionJenga, Connector, UnauthConnectionJenga,
};

#[derive(Default)]
pub struct ConnectionManager<C: Connector + Copy + Default> {
    connector: C,
    unauth_conns: Arc<scc::HashMap<Server, UnauthConnectionJenga<C>>>,
    auth_conns: Arc<scc::HashMap<Arc<Profile>, AuthConnectionJenga<C>>>,
}

impl<C: Connector + Copy + Default> ConnectionManager<C> {
    pub fn new() -> Self {
        Self {
            connector: C::default(),
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
        let msg = ConnectionServiceMessage::Listen(blinded_address, listener_tx);

        let req = if let Some(conn) = self.unauth_conns.get_async(server).await {
            conn.get().request(msg).await?
        } else {
            let ws =
                UnauthConnectionJenga::new(self.connector, server.ws_url_unauth().clone()).await?;
            let resp = ws.request(msg).await;
            let _ = self.unauth_conns.insert_async(server.clone(), ws).await;

            resp?
        };

        let Message::Unauth(UnauthRequest::ChatService(ChatServiceMessage::ListenStarted(
            listener_id,
        ))) = req
        else {
            bail!("Listen failed: {req:?}")
        };

        Ok(listener_id)
    }

    pub async fn stop_listen(
        &self,
        server: &Server,
        listener_id: ListenerId,
    ) -> anyhow::Result<()> {
        let msg = ConnectionServiceMessage::StopListen(listener_id);

        if let Some(conn) = self.unauth_conns.get_async(server).await {
            conn.get().request(msg).await?;
        } else {
            let ws =
                UnauthConnectionJenga::new(self.connector, server.ws_url_unauth().clone()).await?;

            let _resp = ws.request(msg).await?;
            let _ = self.unauth_conns.insert_async(server.clone(), ws).await;
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use lib::crypto::{rng::random_bytes, usernames::UsernameHash};

    use crate::{account::register, net::websocket::WebsocketManager};

    use super::*;

    #[tokio::test]
    /// Test whether open unauthenticated connections are correctly reused
    async fn integration_unauth_duplicate_conns() {
        let server = Server::localhost();
        let manager = WebsocketManager::new();

        assert_eq!(manager.unauth_conns.len(), 0);
        assert_eq!(manager.auth_conns.len(), 0);

        // Dummy request
        let _ = manager
            .request_unauth(&server, UnauthRequest::NoAccount)
            .await
            .expect("Server is open, connection works");

        assert_eq!(manager.unauth_conns.len(), 1);
        assert_eq!(manager.auth_conns.len(), 0);

        // Other dummy request. Should not create a new connection...
        let _ = manager
            .request_unauth(&server, UnauthRequest::NoAccount)
            .await
            .expect("Server is open, connection works");

        assert_eq!(manager.unauth_conns.len(), 1);
        assert_eq!(manager.auth_conns.len(), 0);
    }

    #[tokio::test]
    /// Test whether open authenticated connections are correctly reused
    async fn integration_auth_duplicate_conns() {
        let profile: Arc<Profile> =
            register::create_account(&Server::localhost(), UsernameHash(random_bytes::<32>()))
                .await
                .unwrap()
                .into();
        let manager = WebsocketManager::new();

        assert_eq!(manager.unauth_conns.len(), 0);
        assert_eq!(manager.auth_conns.len(), 0);

        // Dummy request
        let _ = manager
            .request_auth(profile.clone(), AuthRequest::KeyPackageAlreadyUploaded)
            .await
            .expect("Server is open, connection works");

        assert_eq!(manager.unauth_conns.len(), 0);
        assert_eq!(manager.auth_conns.len(), 1);

        // Other dummy request. Should not create a new connection...
        let _ = manager
            .request_auth(profile.clone(), AuthRequest::KeyPackageAlreadyUploaded)
            .await
            .expect("Server is open, connection works");

        assert_eq!(manager.unauth_conns.len(), 0);
        assert_eq!(manager.auth_conns.len(), 1);
    }

    #[tokio::test]
    /// If a connection closes, then request() should not fail
    async fn integration_request_after_conn_close() {
        let server = Server::localhost();
        let manager = WebsocketManager::new();

        // Ok
        let _ = manager
            .request_unauth(&server, UnauthRequest::NoAccount)
            .await
            .expect("Server is open, connection works");

        // Close connection "unexpectedly"

        let conn_id_1 = {
            let conn_ref = manager
                .unauth_conns
                .get(&server)
                .expect("Connection is there");

            // We must be careful about deadlocks
            let conn = conn_ref.get().get_service();

            let lock = conn.lock().await;
            lock.cancellation_token.cancel();

            lock.connection_id
        };

        // Requests still pass through because a new connection is made
        let _ = manager
            .request_unauth(&server, UnauthRequest::NoAccount)
            .await
            .expect("Server is open, connection works");

        let conn_id_2 = {
            let conn_ref = manager
                .unauth_conns
                .get(&server)
                .expect("Connection is there");

            // We must be careful about deadlocks
            let conn = conn_ref.get().get_service();
            let lock = conn.lock().await;

            lock.connection_id
        };

        assert_ne!(
            conn_id_1, conn_id_2,
            "A new connection should have been made"
        );
    }
}
