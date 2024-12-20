use std::{convert::Infallible, pin::Pin, task::Poll};

use futures_util::{Sink, Stream};
use lib::{
    api::messages::{Message, MessageWire, ServiceError},
    crypto::challenge::AuthChallenge,
};

use crate::net::{connection::Connection, raw_connection::RawConnection, ConnectionError};

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

pub struct FakeConnector;
impl jenga::Service<String> for FakeConnector {
    type Response = Connection;
    type Error = ConnectionError;

    async fn request(&self, _msg: String) -> Result<Self::Response, Self::Error> {
        let stream = FakeConnection(scc::Bag::new());
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

pub struct FakeAuthenticatedConnector;
impl jenga::Service<String> for FakeAuthenticatedConnector {
    type Response = Connection;
    type Error = ConnectionError;

    async fn request(&self, _msg: String) -> Result<Self::Response, Self::Error> {
        let stream = FakeAuthenticatedConnection(scc::Bag::new(), ChallengeState::NotStarted, None);
        Ok(RawConnection::start(Box::pin(stream)).into())
    }
}

mod tests {
    #[tokio::test]
    /// Testing what happens if the connection drops before we try to retrieve the response
    /// Rust lazily evalues .await functions, so the request_unauthenticated actually only occurs
    /// after removing the connection, meaning it should automatically make a new connection.
    pub async fn integration_fault_connection_drop_while_receive() {
        todo!("we need close API to do this test");
    }

    #[tokio::test]
    pub async fn integration_test_close_connection() {
        todo!("we need close API to do this test");
    }
}
