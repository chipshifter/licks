use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use lib::api::connection::Message;
use tokio_tungstenite::{connect_async, tungstenite::Message as TungsteniteMessage};

use crate::manager::account::Profile;

use super::connection::Connection;
use super::connection::RawConnection;
use super::Connector;
use super::ServerConnectionError;

#[derive(Debug, Default, Clone, Copy)]
/// [`Connection`] holds all the relevant information,
/// so we keep this struct empty
pub struct WebsocketConnector;

impl Connector for WebsocketConnector {}

// Unauthenticated connections
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

// authenticated connections: unauth connections + a challenge
impl jenga::Service<Arc<Profile>> for WebsocketConnector {
    type Response = Connection;
    type Error = ServerConnectionError;

    async fn request(&self, msg: Arc<Profile>) -> Result<Self::Response, Self::Error> {
        let unauth_conn = <WebsocketConnector as jenga::Service<String>>::request(
            &self,
            msg.get_server().ws_url_auth(),
        )
        .await?;

        let challenge_1 = unauth_conn
            .request(Message::GetChallenge.into())
            .await
            .expect("todo");

        let Message::Challenge(server_challenge) = challenge_1 else {
            todo!();
        };

        let challenge_response = msg.get_auth_challenge_response(server_challenge);

        let challenge_2 = unauth_conn
            .request(Message::ChallengeResponse(challenge_response).into())
            .await
            .expect("todo");

        match challenge_2 {
            Message::Ok => Ok(unauth_conn),
            _ => todo!(),
        }
    }
}
