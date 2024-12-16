use anyhow::anyhow;
use futures_util::Future;
use jenga::Service;
use lib::api::connection::{
    AuthRequest, ChatServiceMessage, ClientRequestId, ListenerId, Message, MessageWire,
    UnauthRequest, MAX_CONNECTION_TIMEOUT_SECS, MIN_REQUEST_TIMEOUT_SECS,
};
use lib::api::server::Server;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::Sender;

use super::account::Profile;
use super::listener::ListenerMessage;
use crate::manager::error::Result;
use crate::net::connection::Connection;
use crate::net::manager::WebsocketManager;
use crate::net::websocket::WebsocketConnector;
use crate::net::Connector;
#[cfg(test)]
use crate::tests::connections::{FakeAuthenticatedConnector, FakeConnector};
use lib::crypto::blinded_address::BlindedAddressPublic;

pub struct ConnectionManager {
    unauthenticated_connections: scc::HashMap<Server, Arc<Connection>>,
    authenticated_connections: scc::HashMap<Arc<Profile>, Arc<Connection>>,
    ws_manager: Arc<WebsocketManager>,
    connection_mode: ConnectionMode,
    max_retry_attempts: u32,
    max_timeout_secs: Duration,
}

/// Tell the connection manager which type of connection we want to use.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnectionMode {
    #[default]
    WebSocket,
    #[cfg(test)]
    FakeConnection,
    #[cfg(test)]
    FakeAuthenticatedConnection,
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
        ConnectionManager::new(ConnectionMode::default(), None, None)
    }
}

impl ConnectionManager {
    pub fn new(
        connection_mode: ConnectionMode,
        retry_attempts: Option<u32>,
        max_timeout_secs: Option<Duration>,
    ) -> ConnectionManager {
        ConnectionManager {
            unauthenticated_connections: scc::HashMap::new(),
            authenticated_connections: scc::HashMap::new(),
            ws_manager: Arc::new(WebsocketManager::new()),
            connection_mode,
            max_retry_attempts: retry_attempts.unwrap_or(5),
            max_timeout_secs: max_timeout_secs.unwrap_or(MAX_CONNECTION_TIMEOUT_SECS),
        }
    }

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
                .request_with_connection(&conn, Message::GetChallenge.into(), None, None)
                .await?;

            match chall {
                Message::Challenge(challenge) => {
                    let response = profile.get_auth_challenge_response(challenge);

                    match self
                    .request_with_connection(&conn, Message::ChallengeResponse(response).into(), None, None)
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
        match self.connection_mode {
            ConnectionMode::WebSocket => {
                let ws = WebsocketConnector;
                let ws_conn = ws.start_connection(url).await?;

                Ok(Arc::new(ws_conn))
            }
            #[cfg(test)]
            ConnectionMode::FakeConnection => {
                let fake = FakeConnector;
                let fake_conn = fake.start_connection(url).await?;

                Ok(Arc::new(fake_conn))
            }
            #[cfg(test)]
            ConnectionMode::FakeAuthenticatedConnection => {
                let fake = FakeAuthenticatedConnector;
                let fake_conn = fake.start_connection(url).await?;

                Ok(Arc::new(fake_conn))
            }
        }
    }

    async fn request_with_connection(
        &self,
        connection: &Connection,
        wire: MessageWire,
        _timeout_secs: Option<Duration>,
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
    async fn request_with_retry<
        'a,
        'b,
        GetConnFut: Future<Output = Result<Arc<Connection>>>,
        Key: 'b,
        GetConn: Fn(&'a Self, &'b Key) -> GetConnFut,
        RemoveConnFut: Future<Output = ()>,
        RemoveConn: Fn(&'a Self, &'b Key) -> RemoveConnFut,
    >(
        &'a self,
        key: &'b Key,
        message: Message,
        get_connection_function: GetConn,
        remove_connection_function: RemoveConn,
        listener: Option<Sender<ListenerMessage>>,
    ) -> Result<Message> {
        let request_id = ClientRequestId::generate();
        let wire = MessageWire(request_id, message);
        let mut conn = get_connection_function(self, key).await?;

        let mut tries = 1;
        let mut request = Self::request_with_connection(
            self,
            &conn,
            wire.clone(),
            Some(MIN_REQUEST_TIMEOUT_SECS),
            listener,
        )
        .await;

        while tries < self.max_retry_attempts && request.is_err() {
            let timeout_secs = self.max_timeout_secs / (self.max_retry_attempts - tries).pow(2);
            log::warn!(
                "Retrying request {:?}, timeout set to {:?}, retry attempt #{}/#{}",
                request_id,
                timeout_secs,
                tries,
                self.max_retry_attempts
            );

            conn = if conn.is_open() {
                conn
            } else {
                remove_connection_function(self, key).await;

                get_connection_function(self, key).await?
            };

            tries += 1;
            request =
                Self::request_with_connection(self, &conn, wire.clone(), Some(timeout_secs), None)
                    .await;
        }

        Ok(request?)
    }

    #[inline]
    pub async fn request_unauthenticated(
        &self,
        server: &Server,
        request: UnauthRequest,
    ) -> Result<Message> {
        if self.connection_mode == ConnectionMode::WebSocket {
            Ok(self.ws_manager.request_unauth(server, request).await?)
        } else {
            Self::request_with_retry(
                self,
                server,
                Message::Unauth(request),
                Self::get_unauthenticated_connection,
                Self::remove_unauthenticated_connection,
                None,
            )
            .await
        }
    }

    #[inline]
    pub async fn request_authenticated(
        &self,
        profile: Arc<Profile>,
        request: AuthRequest,
    ) -> Result<Message> {
        Self::request_with_retry(
            self,
            &profile,
            Message::Auth(request),
            Self::get_authenticated_connection,
            Self::remove_authenticated_connection,
            None,
        )
        .await
    }

    /// Returns the `RequestId` that is listening.
    pub async fn listen_to_blinded_address(
        &self,
        server: &Server,
        blinded_address: BlindedAddressPublic,
        listener_tx: Sender<ListenerMessage>,
    ) -> Result<ListenerId> {
        let listener_id = ListenerId::generate();

        let _ = Self::request_with_retry(
            self,
            server,
            Message::Unauth(UnauthRequest::ChatService(
                ChatServiceMessage::SubscribeToAddress(listener_id, blinded_address),
            )),
            Self::get_unauthenticated_connection,
            Self::remove_unauthenticated_connection,
            Some(listener_tx),
        )
        .await?;

        Ok(listener_id)
    }

    /// Stop listening to a blinded address. The [`RequestId`] should be
    /// the one that is listening.
    ///
    /// NOTE: The server always returns [`Message::Ok`], even if the [`RequestId`]
    /// given wasn't listening to anything.
    pub async fn stop_listening(&self, server: &Server, listener_id: ListenerId) -> Result<()> {
        // Ignore response, server always returns Message::Ok
        let _resp = Self::request_with_retry(
            self,
            server,
            Message::Unauth(UnauthRequest::ChatService(
                ChatServiceMessage::StopListening(listener_id),
            )),
            Self::get_unauthenticated_connection,
            Self::remove_unauthenticated_connection,
            None,
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

    pub async fn integration_test_timeout(connection_mode: ConnectionMode) {
        let conns = ConnectionManager::new(connection_mode, Some(1), Some(Duration::from_secs(2)));
        let server = Server::localhost();

        let conn = conns
            .get_unauthenticated_connection(&server)
            .await
            .expect("localhost server should be open");

        assert!(conn.is_open());

        assert!(conns
            .request_with_connection(&conn, Message::Ignore.into(), None, None)
            .await
            .is_err());
    }

    pub async fn integration_test_heartbeat(connection_mode: ConnectionMode) {
        let conns = ConnectionManager::new(connection_mode, None, None);
        let server = Server::localhost();

        let conn = conns
            .get_unauthenticated_connection(&server)
            .await
            .expect("localhost server should be open");

        tokio::time::sleep(Duration::from_secs(60)).await;

        assert!(conn.is_open());
        assert_eq!(
            conns
                .request_with_connection(&conn, Message::Ok.into(), None, None)
                .await
                .expect("Connection should still be open"),
            Message::Error(ServiceError::InvalidOperation)
        );
    }

    pub async fn integration_authenticated_channel(connection_mode: ConnectionMode) {
        let conns = ConnectionManager::new(connection_mode, None, None);

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
    #[tokio::test(flavor = "multi_thread")]
    pub async fn integration_test_heartbeat_all_impls() {
        integration_test_heartbeat(ConnectionMode::WebSocket).await;
    }

    #[cfg(feature = "integration-testing")]
    #[tokio::test(flavor = "multi_thread")]
    pub async fn integration_test_timeout_all_impls() {
        integration_test_timeout(ConnectionMode::WebSocket).await;
    }

    #[cfg(feature = "integration-testing")]
    #[tokio::test(flavor = "multi_thread")]
    pub async fn integration_test_authenticated_all_impls() {
        integration_authenticated_channel(ConnectionMode::WebSocket).await;
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
