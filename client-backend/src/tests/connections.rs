use std::{convert::Infallible, pin::Pin, task::Poll};

use futures_util::{Sink, Stream};
use lib::{
    api::connection::{Message, MessageWire, ServiceError},
    crypto::challenge::AuthChallenge,
};

use crate::net::{
    connection::{Connection, RawConnection},
    ConnectionStarter, ServerConnectionError,
};

/// A fake connection (which is just a stream) used to test the connection manager.
/// It takes in bytes in input and output. The connection deserializes the input and
/// sends back a '`InvalidOperation`' message back with the associated [`RequestId`].
/// This is "multi threaded" and requests don't come back out in the order they came in.
pub struct FakeConnection(scc::Bag<Vec<u8>>);

enum ChallengeState {
    NotStarted,
    Waiting,
    Completed,
    Failed,
}

pub struct FakeAuthenticatedConnection(scc::Bag<Vec<u8>>, ChallengeState, Option<AuthChallenge>);

impl Sink<Vec<u8>> for FakeConnection {
    type Error = Infallible;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.0.push(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0 = scc::Bag::new();
        Poll::Ready(Ok(()))
    }
}

impl Stream for FakeConnection {
    type Item = Vec<u8>;

    fn poll_next(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let wire = match self.0.pop() {
            Some(msg) => MessageWire::from_bytes(&msg).ok(),
            None => None,
        };

        if let Some(req) = wire {
            Poll::Ready(Some(
                MessageWire(req.0, Message::Error(ServiceError::InvalidOperation)).to_bytes(),
            ))
        } else {
            Poll::Ready(None)
        }
    }
}

#[async_trait::async_trait]
impl ConnectionStarter for FakeConnection {
    async fn start_connection(_url: String) -> Result<Connection, ServerConnectionError> {
        let stream = Self(scc::Bag::new());
        Ok(RawConnection::start(Box::pin(stream)).into())
    }
}

impl Sink<Vec<u8>> for FakeAuthenticatedConnection {
    type Error = Infallible;

    fn poll_ready(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Vec<u8>) -> Result<(), Self::Error> {
        self.0.push(item);
        Ok(())
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        self.0 = scc::Bag::new();
        Poll::Ready(Ok(()))
    }
}

impl Stream for FakeAuthenticatedConnection {
    type Item = Vec<u8>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let wire = match self.0.pop() {
            Some(msg) => MessageWire::from_bytes(&msg).ok(),
            None => None,
        };

        if let Some(req) = wire {
            match self.1 {
                ChallengeState::NotStarted => {
                    if req.1.eq(&Message::GetChallenge) {
                        let challenge = AuthChallenge::generate();
                        self.2 = Some(challenge);
                        self.1 = ChallengeState::Waiting;
                        Poll::Ready(Some(
                            MessageWire(req.0, Message::Challenge(challenge)).to_bytes(),
                        ))
                    } else {
                        self.1 = ChallengeState::Failed;
                        Poll::Ready(None)
                    }
                }
                ChallengeState::Waiting => {
                    if let Message::ChallengeResponse(resp) = req.1 {
                        if resp
                            .verify(self.2.expect("Challenge was generated"))
                            .is_ok()
                        {
                            self.1 = ChallengeState::Completed;
                            Poll::Ready(Some(MessageWire(req.0, Message::Ok).to_bytes()))
                        } else {
                            self.1 = ChallengeState::Failed;
                            Poll::Ready(None)
                        }
                    } else {
                        self.1 = ChallengeState::Failed;
                        Poll::Ready(None)
                    }
                }
                ChallengeState::Completed => Poll::Ready(Some(
                    MessageWire(req.0, Message::Error(ServiceError::InvalidOperation)).to_bytes(),
                )),
                ChallengeState::Failed => Poll::Ready(None),
            }
        } else {
            Poll::Ready(None)
        }
    }
}

#[async_trait::async_trait]
impl ConnectionStarter for FakeAuthenticatedConnection {
    async fn start_connection(_url: String) -> Result<Connection, ServerConnectionError> {
        let stream = Self(scc::Bag::new(), ChallengeState::NotStarted, None);
        Ok(RawConnection::start(Box::pin(stream)).into())
    }
}

mod tests {
    use std::{sync::Arc, time::Duration};

    use lib::{
        api::{
            connection::{AuthRequest, UnauthRequest},
            server::Server,
        },
        util::uuid::generate_uuid,
    };
    use tokio::task::JoinSet;

    use crate::{
        manager::connections::{ConnectionManager, ConnectionMode},
        tests::utils::fake_profile,
    };

    #[tokio::test(flavor = "multi_thread")]
    /// Sends a request at the same time a connection closes.
    /// The connection manager is expected to automatically retry the request
    /// and if necessary will restart the connection a few times.
    pub async fn non_deterministic_stress_request_while_close() {
        let conns = Arc::new(ConnectionManager::new(
            ConnectionMode::FakeConnection,
            None,
            None,
        ));

        // this is a sort of race so we test many times and hope for the best
        let attempts = 100;
        for _ in 0..attempts {
            let conns = conns.clone();
            let server = Server::localhost();
            let conn = conns
                .get_unauthenticated_connection(&server)
                .await
                .expect("server is open on localhost");

            let request = tokio::spawn(async move {
                conns
                    .request_unauthenticated(&server, UnauthRequest::NoAccount)
                    .await
                    .expect("request should be retried on a new connection if failed")
            });

            let close_conn = tokio::spawn(async move {
                conn.close();
            });

            let (one, two) = tokio::join!(request, close_conn);
            assert!(one.is_ok());
            assert!(two.is_ok());
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    /// Unrealistically tries many many connections/requests at once to see
    /// how fast and how well the ConnectionManager handles multi-threaded loads.
    pub async fn stress_many_unauthenticated_connections() {
        let conns = Arc::new(ConnectionManager::new(
            ConnectionMode::FakeConnection,
            None,
            None,
        ));

        let count = 1000;
        let mut set = JoinSet::new();
        for _ in 0..count {
            let conns = conns.clone();
            set.spawn(async move {
                let server = Server {
                    host: generate_uuid().to_string(),
                    unauth_endpoint_port: 1234,
                    auth_endpoint_port: 12345,
                };

                conns
                    .request_unauthenticated(&server, UnauthRequest::NoAccount)
                    .await
                    .expect("Server responds");
            });
        }

        while let Some(join) = set.join_next().await {
            join.expect("connection shouldn't crash");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    /// Unrealistically tries many many connections/requests at once to see
    /// how fast and how well the ConnectionManager handles multi-threaded loads.
    pub async fn stress_many_authenticated_connections() {
        let conns = Arc::new(ConnectionManager::new(
            ConnectionMode::FakeAuthenticatedConnection,
            None,
            None,
        ));

        let count = 100;
        let mut set = JoinSet::new();
        for _ in 0..count {
            let conns = conns.clone();
            set.spawn(async move {
                let server = Server {
                    host: generate_uuid().to_string(),
                    unauth_endpoint_port: 1234,
                    auth_endpoint_port: 12345,
                };

                let profile = Arc::new(fake_profile(server));

                conns
                    .request_authenticated(profile, AuthRequest::UsernameIsAlreadyTaken)
                    .await
                    .expect("Server responds");
            });
        }

        while let Some(join) = set.join_next().await {
            join.expect("connection shouldn't crash");
        }
    }

    #[tokio::test]
    /// Testing what happens if the connection drops before we try to retrieve the response
    /// Rust lazily evalues .await functions, so the request_unauthenticated actually only occurs
    /// after removing the connection, meaning it should automatically make a new connection.
    pub async fn integration_fault_connection_drop_while_receive() {
        let conns = ConnectionManager::new(ConnectionMode::FakeConnection, None, None);
        let server = Server::localhost();

        let _ = conns
            .request_unauthenticated(&server, UnauthRequest::NoAccount)
            .await
            .expect("fake connections will always open");

        let req_future = conns.request_unauthenticated(&server, UnauthRequest::NoAccount);

        conns.remove_unauthenticated_connection(&server).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        req_future.await.expect("We get a response from the server");
    }

    #[tokio::test]
    pub async fn integration_test_close_connection() {
        let conns = ConnectionManager::new(ConnectionMode::FakeConnection, None, None);
        let server = Server::localhost();

        let conn = conns
            .get_unauthenticated_connection(&server)
            .await
            .expect("fake connections will always open");

        assert!(conn.is_open());

        conn.close();

        // wait a bit to make sure it finishes
        // (this isn't instant)
        tokio::time::sleep(Duration::from_millis(100)).await;

        assert!(!conn.is_open());
    }
}
