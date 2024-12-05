use uuid::Uuid;

use crate::{
    api::{
        connection::{Message, MessageWire},
        group::DeliveryStamp,
    },
    crypto::usernames::UsernameHash,
    error::ProtoError,
};

use super::{ClientRequestId, ListenerId, ServiceError};

pub use prost::Message as ProstMessage;

#[allow(warnings)]
mod wire {
    include!("../../generated/wire.rs");
}

pub use wire::*;

impl From<MessageWire> for LicksMessageWire {
    fn from(value: MessageWire) -> Self {
        LicksMessageWire {
            request_id: Some(value.0 .0.into_bytes().to_vec()),
            licks_message_body: Some(value.1.into()),
        }
    }
}

impl TryFrom<LicksMessageWire> for MessageWire {
    type Error = ProtoError;

    fn try_from(value: LicksMessageWire) -> Result<Self, Self::Error> {
        let req_id_bytes = value.request_id.ok_or(ProtoError)?;
        let req_id = ClientRequestId(Uuid::from_slice(&req_id_bytes).map_err(|_| ProtoError)?);
        Ok(Self(
            req_id,
            value.licks_message_body.ok_or(ProtoError)?.try_into()?,
        ))
    }
}

impl From<Message> for licks_message_wire::LicksMessageBody {
    fn from(value: Message) -> Self {
        match value {
            Message::Error(error) => Self::Error(LicksApiError::from(error) as i32),
            Message::Ping(bytes) => Self::Ping(bytes),
            Message::Pong(bytes) => Self::Pong(bytes),
            Message::Ignore => Self::Empty(EmptyMessageBody::Ignore.into()),
            Message::Bye => Self::Empty(EmptyMessageBody::Bye.into()),
            Message::Ok => Self::Empty(EmptyMessageBody::Ok.into()),
            Message::Auth(auth) => Self::Authenticated(auth.into()),
            Message::Unauth(unauth) => Self::Unauthenticated(unauth.into()),
            Message::GetChallenge => Self::Empty(EmptyMessageBody::GetChallenge.into()),
            Message::Challenge(challenge) => Self::Challenge(challenge.as_bytes().into()),
            Message::ChallengeResponse(challenge_response) => {
                Self::ChallengeResponse(challenge_response.into())
            }
        }
    }
}

impl From<super::AuthRequest> for AuthenticatedChannelMessage {
    fn from(value: super::AuthRequest) -> Self {
        let inner = match value {
            super::AuthRequest::SetUsername(username) => {
                authenticated_channel_message::Inner::SetUsername(username.as_ref().into())
            }
            super::AuthRequest::RemoveUsername(username) => {
                authenticated_channel_message::Inner::RemoveUsername(username.as_ref().into())
            }
            super::AuthRequest::UsernameIsAlreadyYours => {
                authenticated_channel_message::Inner::UsernameIsAlreadyYours(Empty {})
            }
            super::AuthRequest::UsernameIsAlreadyTaken => {
                authenticated_channel_message::Inner::UsernameIsAlreadyTaken(Empty {})
            }
            super::AuthRequest::UploadKeyPackages(keypackage) => {
                authenticated_channel_message::Inner::UploadKeyPackages(KeyPackages {
                    inner: keypackage,
                })
            }
            super::AuthRequest::KeyPackageAlreadyUploaded => {
                authenticated_channel_message::Inner::KeyPackageAlreadyUploaded(Empty {})
            }
        };
        Self { inner: Some(inner) }
    }
}

impl TryFrom<AuthenticatedChannelMessage> for super::AuthRequest {
    type Error = ProtoError;

    fn try_from(value: AuthenticatedChannelMessage) -> Result<Self, Self::Error> {
        Ok(match value.inner.ok_or(ProtoError)? {
            authenticated_channel_message::Inner::SetUsername(username) => {
                Self::SetUsername(UsernameHash(username.try_into().map_err(|_| ProtoError)?))
            }
            authenticated_channel_message::Inner::RemoveUsername(username) => {
                Self::RemoveUsername(UsernameHash(username.try_into().map_err(|_| ProtoError)?))
            }
            authenticated_channel_message::Inner::UsernameIsAlreadyYours(_) => {
                Self::UsernameIsAlreadyYours
            }
            authenticated_channel_message::Inner::UsernameIsAlreadyTaken(_) => {
                Self::UsernameIsAlreadyTaken
            }
            authenticated_channel_message::Inner::UploadKeyPackages(keypackage) => {
                Self::UploadKeyPackages(keypackage.inner)
            }
            authenticated_channel_message::Inner::KeyPackageAlreadyUploaded(_) => {
                Self::KeyPackageAlreadyUploaded
            }
        })
    }
}

impl From<super::UnauthRequest> for UnauthenticatedChannelMessage {
    fn from(value: super::UnauthRequest) -> Self {
        let inner = match value {
            super::UnauthRequest::Registration(registration) => {
                unauthenticated_channel_message::Inner::Registration(registration.into())
            }
            super::UnauthRequest::GetKeyPackage(acc_id) => {
                unauthenticated_channel_message::Inner::GetKeyPackage(acc_id.into())
            }
            super::UnauthRequest::HereIsKeyPackage(keypackage) => {
                unauthenticated_channel_message::Inner::HereIsKeyPackage(keypackage)
            }
            super::UnauthRequest::NoKeyPackage => {
                unauthenticated_channel_message::Inner::NoKeyPackage(Empty {})
            }
            super::UnauthRequest::GetAccountFromUsername(username) => {
                unauthenticated_channel_message::Inner::GetAccountFromUsername(
                    username.as_ref().into(),
                )
            }
            super::UnauthRequest::HereIsAccount(acc_id) => {
                unauthenticated_channel_message::Inner::HereIsAccount(acc_id.into())
            }
            super::UnauthRequest::NoAccount => {
                unauthenticated_channel_message::Inner::NoAccount(Empty {})
            }
            super::UnauthRequest::ChatService(msg) => {
                unauthenticated_channel_message::Inner::ChatService(msg.into())
            }
        };
        Self { inner: Some(inner) }
    }
}

impl TryFrom<UnauthenticatedChannelMessage> for super::UnauthRequest {
    type Error = ProtoError;

    fn try_from(value: UnauthenticatedChannelMessage) -> Result<Self, Self::Error> {
        Ok(match value.inner.ok_or(ProtoError)? {
            unauthenticated_channel_message::Inner::Registration(registration) => {
                Self::Registration(registration.try_into()?)
            }
            unauthenticated_channel_message::Inner::GetKeyPackage(acc_id) => {
                Self::GetKeyPackage(acc_id.try_into()?)
            }
            unauthenticated_channel_message::Inner::HereIsKeyPackage(keypackage) => {
                Self::HereIsKeyPackage(keypackage)
            }
            unauthenticated_channel_message::Inner::NoKeyPackage(_) => Self::NoKeyPackage,
            unauthenticated_channel_message::Inner::GetAccountFromUsername(username) => {
                Self::GetAccountFromUsername(
                    TryInto::<[u8; 32]>::try_into(username)
                        .map_err(|_| ProtoError)?
                        .into(),
                )
            }
            unauthenticated_channel_message::Inner::HereIsAccount(acc_id) => {
                Self::HereIsAccount(acc_id.try_into()?)
            }
            unauthenticated_channel_message::Inner::NoAccount(_) => Self::NoAccount,
            unauthenticated_channel_message::Inner::ChatService(msg) => {
                Self::ChatService(msg.try_into()?)
            }
        })
    }
}

impl From<crate::api::registration::RegistrationService> for RegistrationService {
    fn from(value: crate::api::registration::RegistrationService) -> Self {
        Self {
            stage: Some(value.into()),
        }
    }
}

impl TryFrom<RegistrationService> for crate::api::registration::RegistrationService {
    type Error = ProtoError;

    fn try_from(value: RegistrationService) -> Result<Self, Self::Error> {
        Ok(match value.stage.ok_or(ProtoError)? {
            registration_service::Stage::StageOne(stage1) => {
                Self::Stage1(match stage1.inner.ok_or(ProtoError)? {
                    stage1::Inner::HereIsMyAccountPublicKey(bytes) => {
                        crate::api::registration::Stage1Message::HereIsMyAccountPublicKey(bytes)
                    }
                    stage1::Inner::HereIsYourAccountId(account_id) => {
                        crate::api::registration::Stage1Message::HereIsYourAccountId(
                            account_id.try_into()?,
                        )
                    }
                })
            }
            registration_service::Stage::StageTwo(stage2) => Self::Stage2(stage2.try_into()?),
            registration_service::Stage::StageThree(stage3) => Self::Stage3(stage3.try_into()?),
        })
    }
}

impl TryFrom<licks_message_wire::LicksMessageBody> for Message {
    type Error = ProtoError;

    fn try_from(
        value: licks_message_wire::LicksMessageBody,
    ) -> Result<Self, <Self as TryFrom<licks_message_wire::LicksMessageBody>>::Error> {
        Ok(match value {
            licks_message_wire::LicksMessageBody::Error(error) => Self::Error(
                ServiceError::try_from(LicksApiError::try_from(error).map_err(|_| ProtoError)?)?,
            ),
            licks_message_wire::LicksMessageBody::Authenticated(auth) => {
                Self::Auth(auth.try_into()?)
            }
            licks_message_wire::LicksMessageBody::Unauthenticated(unauth) => {
                Self::Unauth(unauth.try_into()?)
            }
            licks_message_wire::LicksMessageBody::Challenge(challenge) => {
                Self::Challenge(crate::crypto::challenge::AuthChallenge(
                    challenge.try_into().map_err(|_| ProtoError)?,
                ))
            }
            licks_message_wire::LicksMessageBody::ChallengeResponse(challenge_response) => {
                Self::ChallengeResponse(challenge_response.try_into()?)
            }
            licks_message_wire::LicksMessageBody::Ping(bytes) => Self::Ping(bytes),
            licks_message_wire::LicksMessageBody::Pong(bytes) => Self::Pong(bytes),
            licks_message_wire::LicksMessageBody::Empty(empties) => {
                match EmptyMessageBody::try_from(empties).map_err(|_| ProtoError)? {
                    EmptyMessageBody::Ignore => Self::Ignore,
                    EmptyMessageBody::GetChallenge => Self::GetChallenge,
                    EmptyMessageBody::Ok => Self::Ok,
                    EmptyMessageBody::Bye => Self::Bye,
                }
            }
        })
    }
}

impl From<super::ChatServiceMessage> for ChatServiceMessage {
    fn from(value: super::ChatServiceMessage) -> Self {
        let inner = Some(match value {
            super::ChatServiceMessage::RetrieveQueue(request) => {
                chat_service_message::Inner::RetreiveQueue(
                    chat_service_message::GetMessageRequest {
                        blinded_address: Some(request.blinded_address.into()),
                        delivery_id: request.server_delivery_id.to_vec(),
                    },
                )
            }
            super::ChatServiceMessage::SubscribeToAddress(listener_id, blinded_addr) => {
                chat_service_message::Inner::SubscribeToAddress(
                    chat_service_message::StartListeningRequest {
                        listener_id: listener_id.to_vec(),
                        blinded_address: Some(blinded_addr.into()),
                    },
                )
            }
            super::ChatServiceMessage::MlsMessage(delivery_id, bytes) => {
                chat_service_message::Inner::MlsMessage(chat_service_message::MlsMessage {
                    delivery_id: delivery_id.to_vec(),
                    body: bytes,
                })
            }
            super::ChatServiceMessage::QueueDone(count) => {
                chat_service_message::Inner::QueueDone(count)
            }
            super::ChatServiceMessage::QueueEmpty => {
                chat_service_message::Inner::QueueEmpty(Empty {})
            }
            super::ChatServiceMessage::SendMessage(send_message) => {
                chat_service_message::Inner::SendMessage(chat_service_message::SendMessageRequest {
                    proof: Some(send_message.blinded_address_proof.into()),
                })
            }
            super::ChatServiceMessage::StopListening(listener_id) => {
                chat_service_message::Inner::StopListening(chat_service_message::StopListening {
                    listener_id: listener_id.to_vec(),
                })
            }
            super::ChatServiceMessage::Delivered(delivery_stamp) => {
                chat_service_message::Inner::Delivered(delivery_stamp.to_vec())
            }
        });
        Self { inner }
    }
}

impl TryFrom<ChatServiceMessage> for super::ChatServiceMessage {
    type Error = ProtoError;

    fn try_from(value: ChatServiceMessage) -> Result<Self, Self::Error> {
        Ok(match value.inner.ok_or(ProtoError)? {
            chat_service_message::Inner::RetreiveQueue(req) => {
                Self::RetrieveQueue(crate::api::group::GetMessagesRequest {
                    blinded_address: req.blinded_address.ok_or(ProtoError)?.try_into()?,
                    server_delivery_id: req
                        .delivery_id
                        .as_slice()
                        .try_into()
                        .map_err(|()| ProtoError)?,
                })
            }
            chat_service_message::Inner::SubscribeToAddress(req) => Self::SubscribeToAddress(
                ListenerId::try_from(req.listener_id).map_err(|()| ProtoError)?,
                req.blinded_address.ok_or(ProtoError)?.try_into()?,
            ),
            chat_service_message::Inner::MlsMessage(mls_message) => Self::MlsMessage(
                mls_message
                    .delivery_id
                    .as_slice()
                    .try_into()
                    .map_err(|()| ProtoError)?,
                mls_message.body,
            ),
            chat_service_message::Inner::QueueDone(count) => Self::QueueDone(count),
            chat_service_message::Inner::QueueEmpty(_) => Self::QueueEmpty,
            chat_service_message::Inner::SendMessage(send_message) => {
                Self::SendMessage(crate::api::group::SendMessageRequest {
                    blinded_address_proof: send_message.proof.ok_or(ProtoError)?.try_into()?,
                })
            }
            chat_service_message::Inner::StopListening(stop_listening) => Self::StopListening(
                ListenerId::try_from(stop_listening.listener_id).map_err(|()| ProtoError)?,
            ),
            chat_service_message::Inner::Delivered(vec) => {
                Self::Delivered(DeliveryStamp::try_from(vec.as_slice()).map_err(|()| ProtoError)?)
            }
        })
    }
}

impl From<ServiceError> for LicksApiError {
    fn from(value: ServiceError) -> Self {
        match value {
            ServiceError::InvalidRequest => Self::InvalidRequest,
            ServiceError::InvalidCredentials => Self::InvalidCredentials,
            ServiceError::InvalidOperation => Self::InvalidOperation,
            ServiceError::DecodeError => Self::DecodeError,
            ServiceError::InternalError => Self::InternalError,
            ServiceError::ConnectionIsClosed => Self::ConnectionIsClosed,
            ServiceError::UnknownError => Self::UnknownError,
        }
    }
}

impl TryFrom<LicksApiError> for ServiceError {
    type Error = ProtoError;
    fn try_from(value: LicksApiError) -> Result<Self, Self::Error> {
        match value {
            LicksApiError::UninitializedLicksError => Err(ProtoError),
            LicksApiError::InvalidRequest => Ok(Self::InvalidRequest),
            LicksApiError::InvalidCredentials => Ok(Self::InvalidCredentials),
            LicksApiError::InvalidOperation => Ok(Self::InvalidOperation),
            LicksApiError::DecodeError => Ok(Self::DecodeError),
            LicksApiError::InternalError => Ok(Self::InternalError),
            LicksApiError::ConnectionIsClosed => Ok(Self::ConnectionIsClosed),
            LicksApiError::UnknownError => Ok(Self::UnknownError),
        }
    }
}
