use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use lib::api::messages::Message;
use lib::api::messages::MessageWire;
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

use crate::manager::account::Profile;

use super::connection::Connection;
use super::manager::Manager;
use super::raw_connection::RawConnection;
use super::AuthConnector;
use super::ConnectionError;
use super::Connector;
use super::UnauthConnector;

pub type WebsocketManager = Manager<WebsocketConnector>;

#[derive(Debug, Default, Clone, Copy)]
/// [`Connection`] holds all the relevant information,
/// so we keep this struct empty
pub struct WebsocketConnector;

impl UnauthConnector for WebsocketConnector {}
impl AuthConnector for WebsocketConnector {}
impl Connector for WebsocketConnector {}

/// Service for starting unauthenticated connections
impl jenga::Service<String> for WebsocketConnector {
    type Response = Connection;
    type Error = ConnectionError;

    async fn request(&self, msg: String) -> Result<Self::Response, Self::Error> {
        let url = msg;
        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|_| ConnectionError::CouldNotConnect)?;

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

/// Service for starting authenticated connections: unauth connections + complete the challenge
impl jenga::Service<Arc<Profile>> for WebsocketConnector {
    type Response = Connection;
    type Error = ConnectionError;

    async fn request(&self, msg: Arc<Profile>) -> Result<Self::Response, Self::Error> {
        let unauth_conn = <WebsocketConnector as jenga::Service<String>>::request(
            &self,
            msg.get_server().ws_url_auth(),
        )
        .await?;

        let challenge_1 = unauth_conn
            .request(MessageWire::from(Message::GetChallenge).into())
            .await
            .map_err(|_| ConnectionError::AuthChallengeFailed)?;

        let Message::Challenge(server_challenge) = challenge_1 else {
            return Err(ConnectionError::AuthChallengeFailed);
        };

        let challenge_response = msg.get_auth_challenge_response(server_challenge);

        let challenge_2 = unauth_conn
            .request(MessageWire::from(Message::ChallengeResponse(challenge_response)).into())
            .await
            .map_err(|_| ConnectionError::AuthChallengeFailed)?;

        match challenge_2 {
            Message::Ok => Ok(unauth_conn),
            _ => Err(ConnectionError::AuthChallengeFailed),
        }
    }
}

#[cfg(test)]
mod tests {
    use jenga::Service;
    use lib::{api::server::Server, crypto::usernames::Username};

    use crate::account::register;

    use super::*;

    #[tokio::test]
    async fn unauth_connector_works() {
        let url = Server::localhost().ws_url_unauth();
        let connector = WebsocketConnector;
        let conn = connector.request(url).await.expect("Connection works");

        assert!(conn.is_open());
    }

    #[tokio::test]
    async fn auth_connector_works() {
        let server = Server::localhost();
        let profile = register::create_account(
            &server,
            Username::new("auth_conn".to_string())
                .expect("valid username")
                .hash(),
        )
        .await
        .expect("registration works");

        let connector = WebsocketConnector;
        let conn = connector
            .request(Arc::new(profile))
            .await
            .expect("Connection works");

        assert!(conn.is_open());
    }
}
