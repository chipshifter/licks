use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use lib::api::connection::Message;
use lib::api::connection::MessageWire;
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

use crate::manager::account::Profile;

use super::connection::Connection;
use super::raw_connection::RawConnection;
use super::ConnectionError;

#[derive(Debug, Default, Clone, Copy)]
/// [`Connection`] holds all the relevant information,
/// so we keep this struct empty
pub struct WebsocketConnector;

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
