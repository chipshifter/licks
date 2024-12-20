use std::{fmt::Display, time::Duration};

use prost::Message as ProtoMessage;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod proto;

use crate::{
    crypto::{
        blinded_address::BlindedAddressPublic,
        challenge::{AuthChallenge, AuthChallengeResponse},
        listener::{ListenerCommitment, ListenerToken},
        usernames::UsernameHash,
    },
    error::ProtoError,
    identifiers::AccountId,
    util::uuid::{generate_uuid, generate_uuid_v7},
};

use super::{
    group::{DeliveryStamp, GetMessagesRequest, SendMessageRequest},
    registration,
};

/// The maximum hardcoded duration for which a connection to the server
/// can stay alive without sending any requests or pings. After this duration,
/// the connection will disconnect.
pub const MAX_CONNECTION_TIMEOUT_SECS: Duration = Duration::from_secs(40);
pub const MIN_REQUEST_TIMEOUT_SECS: Duration = Duration::from_secs(3);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    /// A message that the server will ignore if received.
    /// This is used for testing timeouts.
    Ignore,
    Bye,
    Ok,
    Error(ServiceError),
    Auth(AuthRequest),
    Unauth(UnauthRequest),
    GetChallenge,
    Challenge(AuthChallenge),
    ChallengeResponse(AuthChallengeResponse),
}

#[derive(thiserror::Error, Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ServiceError {
    #[error("The request was invalid and couldn't be performed")]
    InvalidRequest,
    #[error("Authentication failed")]
    InvalidCredentials,
    #[error("This operation is unknown to the server")]
    InvalidOperation,
    #[error("The message couldn't be read by the server")]
    DecodeError,
    #[error("Internal server error")]
    InternalError,
    #[error("The connection is closed")]
    ConnectionIsClosed,
    #[error("Unknown error")]
    UnknownError,
}

pub type ServiceResult = Result<Message, ServiceError>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AuthRequest {
    SetUsername(UsernameHash),
    RemoveUsername(UsernameHash),
    UsernameIsAlreadyYours,
    UsernameIsAlreadyTaken,
    UploadKeyPackages(Vec<Vec<u8>>),
    KeyPackageAlreadyUploaded,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UnauthRequest {
    Registration(registration::RegistrationService),
    GetKeyPackage(AccountId),
    HereIsKeyPackage(Vec<u8>),
    NoKeyPackage,
    GetAccountFromUsername(UsernameHash),
    HereIsAccount(AccountId),
    NoAccount,
    ChatService(ChatServiceMessage),
}

impl ServiceMessage for AuthRequest {}
impl ServiceMessage for UnauthRequest {}

/// A message trait that will be treated by one of the services on the server.
/// This trait is there to make the server service message handler generic.
pub trait ServiceMessage {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChatServiceMessage {
    RetrieveQueue(GetMessagesRequest),
    /// Authentication payload for the user to start
    /// listening to a blinded address in real time.
    SubscribeToAddress(ListenerCommitment, BlindedAddressPublic),
    ListenStarted(ListenerId),
    StopListening(ListenerId, ListenerToken),
    MlsMessage(DeliveryStamp, Vec<u8>),
    /// Sent by the server after it is done sending the queues messages.
    /// Contains the number of messages we sent after sending the queue
    QueueDone(u64),
    /// Sent by the server if the queue the user wants to retrieve was empty.
    QueueEmpty,
    SendMessage(SendMessageRequest),
    /// The message was successfully sent, and the server returns the delivery
    /// stamp it assigned to the message.
    Delivered(DeliveryStamp),
}

impl ServiceMessage for ChatServiceMessage {}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
/// This is a UUID that allows clients to concurrently determine which messages
/// they receive belongs to which specific request they've made.
///
/// The server *should not* rely on [`RequestId`]'s uniqueness, because two
/// different clients can reuse the same [`RequestId`].
pub struct ClientRequestId(Uuid);

impl Default for ClientRequestId {
    fn default() -> Self {
        Self::generate()
    }
}

impl ClientRequestId {
    /// Returns a `RequestId` with a UUID of 0
    pub const fn nil() -> Self {
        ClientRequestId(Uuid::nil())
    }

    pub const fn is_nil(&self) -> bool {
        self.0.is_nil()
    }

    pub fn generate() -> Self {
        Self(generate_uuid())
    }
}

impl Display for ClientRequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The message structure that is converted to bytes
/// And transmitted over the wire.
/// It might be that the message does not belong to a particular
/// request (ex. a ping), in which case the `Option<RequestId>` is set to `None`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageWire(pub ClientRequestId, pub Message);

impl From<Message> for MessageWire {
    fn from(value: Message) -> Self {
        Self(ClientRequestId(generate_uuid()), value)
    }
}

impl MessageWire {
    pub fn to_bytes(self) -> Vec<u8> {
        proto::LicksMessageWire::from(self).encode_to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        proto::LicksMessageWire::decode(bytes)
            .map_err(|_| ProtoError)?
            .try_into()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
/// An ID associated to a request that starts listening to a blinded address.
/// This ID can then be used to later send a request to stop listening.
pub struct ListenerId(Uuid);

impl Default for ListenerId {
    fn default() -> Self {
        Self::generate()
    }
}

impl ListenerId {
    pub fn generate() -> Self {
        Self(generate_uuid_v7())
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.into_bytes().to_vec()
    }
}

impl TryFrom<Vec<u8>> for ListenerId {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(Uuid::from_slice(&value).map_err(|_| ())?))
    }
}
