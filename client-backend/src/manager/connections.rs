use anyhow::anyhow;
use futures_util::Future;
use jenga::Service;
use lib::api::connection::{
    AuthRequest, ChatServiceMessage, ListenerId, Message, MessageWire, UnauthRequest,
};
use lib::api::server::Server;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use super::account::Profile;
use super::listener::ListenerMessage;
use crate::manager::error::Result;
use crate::net::connection::Connection;
use crate::net::manager::WebsocketManager;
use crate::net::websocket::WebsocketConnector;
use crate::net::Connector;
use lib::crypto::blinded_address::BlindedAddressPublic;

pub struct ConnectionManager {
    unauthenticated_connections: scc::HashMap<Server, Arc<Connection>>,
    authenticated_connections: scc::HashMap<Arc<Profile>, Arc<Connection>>,
    ws_manager: Arc<WebsocketManager>,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("Sending request failed because the connection closed")]
    SendConnectionClosed,
    #[error("Receiving request failed because the connection closed")]
    ReceiveConnectionClosed,
    #[error("The request timed out")]
    Timeout,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        ConnectionManager {
            unauthenticated_connections: scc::HashMap::new(),
            authenticated_connections: scc::HashMap::new(),
            ws_manager: Arc::new(WebsocketManager::new()),
        }
    }
}

impl ConnectionManager {
    #[inline]
    async fn load_or_create_connection<
        K: Debug + Clone + Eq + Hash,
        Fut: Future<Output = Result<()>>,
        F: FnOnce(Arc<Connection>) -> Fut,
    >(
        &self,
        key: &K,
        connection_url: String,
        hashmap: &scc::HashMap<K, Arc<Connection>>,
        run_after_successful_conn: F,
    ) -> Result<Arc<Connection>> {
        let mut remove_old_conn = false;
        if let Some(entry) = hashmap.get_async(key).await {
            let conn = entry.get().clone();
            if conn.is_open() {
                log::debug!("ConnectionManager: Ok");
                return Ok(conn);
            }

            remove_old_conn = true;
        }

        // At this point in the code, we have no connection -- open one
        log::debug!("ConnectionManager: Creating new connection...");

        if remove_old_conn {
            log::debug!("ConnectionManager: We have to remove old connection",);
            // Remove and drop old closed connection
            if let Some((_, conn)) = hashmap.remove_async(key).await {
                log::debug!(
                    "ConnectionManager: Removed connection for {:?} because it was closed",
                    key
                );

                conn.close();
                drop(conn);
            }
        }

        let conn = self.create_connection(connection_url).await?;

        log::debug!("ConnectionManager: Creating new connection succeeded");

        run_after_successful_conn(conn.clone()).await?;

        // Insert new connection. If there was one already somehow
        // (maybe because of a race) close it since it's removed from the db.
        if let Err((_, old_conn)) = hashmap.insert_async(key.clone(), conn.clone()).await {
            log::debug!(
                "ConnectionManager: Race-- Removed old connection even though we just started one"
            );
            let _ = old_conn.close();
            drop(old_conn);
        }

        Ok(conn)
    }

    #[inline]
    pub async fn get_unauthenticated_connection(&self, server: &Server) -> Result<Arc<Connection>> {
        let url = server.ws_url_unauth();

        Self::load_or_create_connection(
            self,
            server,
            url,
            &self.unauthenticated_connections,
            |_| async { Ok(()) },
        )
        .await
    }

    #[inline]
    pub async fn get_authenticated_connection(
        &self,
        profile: &Arc<Profile>,
    ) -> Result<Arc<Connection>> {
        let key = profile.clone();

        let complete_authentication = |conn: Arc<Connection>| async move {
            // Complete authentication challenge
            let chall = self
                .request_with_connection(&conn, Message::GetChallenge.into(), None)
                .await?;

            match chall {
                Message::Challenge(challenge) => {
                    let response = profile.get_auth_challenge_response(challenge);

                    match self
                    .request_with_connection(&conn, Message::ChallengeResponse(response).into(), None)
                    .await? {
                        Message::Ok => Ok(()),
                        other => Err(anyhow!("Challenge reponse failed, got response {other:?}"))
                    }
                },
                other => Err(anyhow!("Tried doing an authentication challenge, but the server responded unexpectedly: {other:?}"))
            }
        };

        let url = key.get_server().ws_url_auth();

        Self::load_or_create_connection(
            self,
            &key,
            url,
            &self.authenticated_connections,
            complete_authentication,
        )
        .await
    }

    async fn create_connection(&self, url: String) -> Result<Arc<Connection>> {
        let ws = WebsocketConnector;
        let ws_conn = ws.start_connection(url).await?;

        Ok(Arc::new(ws_conn))
    }

    async fn request_with_connection(
        &self,
        connection: &Connection,
        wire: MessageWire,
        // If Some, then the connection will start listening to the request
        listener: Option<Sender<ListenerMessage>>,
    ) -> Result<Message> {
        let request_id = wire.0;

        let resp = connection.request(wire).await?;

        if let Some(tx) = listener {
            connection.start_listen(request_id, tx).await;
        }

        Ok(resp)
    }

    #[inline]
    pub async fn request_unauthenticated(
        &self,
        server: &Server,
        request: UnauthRequest,
    ) -> Result<Message> {
        Ok(self.ws_manager.request_unauth(server, request).await?)
    }

    #[inline]
    pub async fn request_authenticated(
        &self,
        profile: Arc<Profile>,
        request: AuthRequest,
    ) -> Result<Message> {
        Ok(self.ws_manager.request_auth(profile, request).await?)
    }

    /// Returns the `RequestId` that is listening.
    pub async fn listen_to_blinded_address(
        &self,
        server: &Server,
        blinded_address: BlindedAddressPublic,
        listener_tx: Sender<ListenerMessage>,
    ) -> Result<ListenerId> {
        let listener_id = ListenerId::generate();

        let connection = self.get_unauthenticated_connection(server).await?;
        self.request_with_connection(
            &connection,
            Message::Unauth(UnauthRequest::ChatService(
                ChatServiceMessage::SubscribeToAddress(listener_id, blinded_address),
            ))
            .into(),
            Some(listener_tx),
        )
        .await?;

        Ok(listener_id)
    }

    /// Stop listening to a blinded address. The [`RequestId`] should be
    /// the one that is listening.
    pub async fn stop_listening(&self, server: &Server, listener_id: ListenerId) -> Result<()> {
        // Ignore response/result. Either it works and we don't need to know about it, or it doesn't
        // and it's fine.
        self.request_unauthenticated(
            server,
            UnauthRequest::ChatService(ChatServiceMessage::StopListening(listener_id)),
        )
        .await?;

        Ok(())
    }

    pub async fn remove_unauthenticated_connection(&self, server: &Server) {
        if let Some((_, conn)) = self.unauthenticated_connections.remove_async(server).await {
            conn.close();
        }
    }

    pub async fn remove_authenticated_connection(&self, profile: &Arc<Profile>) {
        if let Some((_, conn)) = self.authenticated_connections.remove_async(profile).await {
            conn.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::api::connection::ServiceError;

    use super::*;
    use crate::manager::ProfileManager;
    use std::time::Duration;

    #[cfg(feature = "integration-testing")]
    #[tokio::test]
    pub async fn integration_test_heartbeat() {
        let conns = ConnectionManager::default();
        let server = Server::localhost();

        let conn = conns
            .get_unauthenticated_connection(&server)
            .await
            .expect("localhost server should be open");

        tokio::time::sleep(Duration::from_secs(60)).await;

        assert!(conn.is_open());
        assert_eq!(
            conns
                .request_unauthenticated(&server, UnauthRequest::NoAccount.into())
                .await
                .expect("Connection should still be open"),
            Message::Error(ServiceError::InvalidOperation)
        );
    }

    #[cfg(feature = "integration-testing")]
    #[tokio::test]
    pub async fn integration_authenticated_channel() {
        let conns = ConnectionManager::default();

        let manager = ProfileManager::initialise()
            .await
            .expect("Initialisation is OK");

        assert_eq!(conns
            .request_authenticated(manager.get_profile(), AuthRequest::UsernameIsAlreadyYours)
            .await
            .expect("Connection should still be open")
           , Message::Error(ServiceError::InvalidOperation),
        "At this point the connection should be open and valid, so the server replies back to our messages");
    }

    #[cfg(feature = "integration-testing")]
    #[should_panic(expected = "we call panic!() on purpose")]
    #[tokio::test]
    async fn crash_after_client_init() {
        ProfileManager::initialise()
            .await
            .expect("client manager initialises");
        panic!("we call panic!() on purpose");
    }
}
