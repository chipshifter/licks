use futures_util::Future;
use lib::api::connection::{AuthRequest, Message, UnauthRequest};
use lib::api::server::Server;
use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;

use super::account::Profile;
use crate::manager::error::Result;
use crate::net::connection::Connection;
use crate::net::manager::WebsocketManager;
use crate::net::websocket::WebsocketConnector;
use crate::net::Connector;

pub struct ConnectionManager {
    unauthenticated_connections: scc::HashMap<Server, Arc<Connection>>,
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

        let conn = {
            let ws = WebsocketConnector;
            let ws_conn = ws.start_connection(connection_url).await?;
            Arc::new(ws_conn)
        };

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

    pub async fn remove_unauthenticated_connection(&self, server: &Server) {
        if let Some((_, conn)) = self.unauthenticated_connections.remove_async(server).await {
            conn.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::api::connection::ServiceError;

    use super::*;
    use crate::manager::ProfileManager;

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
