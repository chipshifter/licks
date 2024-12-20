use lib::{
    api::{
        group::DeliveryStamp,
        server::Server,
        {proto, proto::ProstMessage},
    },
    error::ProtoError,
    identifiers::AccountId,
};
use serde::{Deserialize, Serialize};

use crate::manager::account::Profile;

pub mod receive;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicksMessageVersion {
    One,
}

impl TryFrom<u32> for LicksMessageVersion {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(LicksMessageVersion::One),
            _ => Err(()),
        }
    }
}

impl From<LicksMessageVersion> for u32 {
    fn from(value: LicksMessageVersion) -> Self {
        match value {
            LicksMessageVersion::One => 1,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MlsApplicationMessage {
    pub client_stamp: DeliveryStamp,
    pub sender_server: Server,
    pub sender_account_id: AccountId,
    pub version: LicksMessageVersion,
    pub content: Content,
}
impl MlsApplicationMessage {
    pub fn to_bytes(self) -> Vec<u8> {
        proto::ApplicationMessage::from(self).encode_to_vec()
    }
}

impl From<MlsApplicationMessage> for proto::ApplicationMessage {
    fn from(value: MlsApplicationMessage) -> Self {
        Self {
            client_timestamp: value.client_stamp.to_vec(),
            sender_server: value.sender_server.to_vec(),
            sender_account_id: Some(value.sender_account_id.into()),
            version: value.version.into(),
            content: Some(value.content.into()),
        }
    }
}

impl TryFrom<proto::ApplicationMessage> for MlsApplicationMessage {
    type Error = ProtoError;

    fn try_from(value: proto::ApplicationMessage) -> Result<Self, Self::Error> {
        if let proto::ApplicationMessage {
            client_timestamp,
            sender_server,
            sender_account_id: Some(sender_account_id),
            version,
            content: Some(content),
        } = value
        {
            Ok(Self {
                client_stamp: client_timestamp
                    .as_slice()
                    .try_into()
                    .map_err(|()| ProtoError)?,
                sender_server: Server::from_vec(sender_server)?,
                sender_account_id: sender_account_id.try_into()?,
                version: version.try_into().map_err(|()| ProtoError)?,
                content: content.try_into()?,
            })
        } else {
            Err(ProtoError)
        }
    }
}

impl From<Content> for proto::Content {
    fn from(value: Content) -> Self {
        let inner = match value {
            Content::BasicText { body } => proto::content::Inner::BasicText(body),
        };
        Self { inner: Some(inner) }
    }
}

impl TryFrom<proto::Content> for Content {
    type Error = ProtoError;

    fn try_from(value: proto::Content) -> Result<Self, Self::Error> {
        Ok(match value.inner.ok_or(ProtoError)? {
            proto::content::Inner::BasicText(text) => Self::BasicText { body: text },
        })
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum Content {
    // For testing and very basic messages support
    BasicText { body: String },
}

pub enum MessageKind {
    PlainText,
}

impl From<MessageKind> for u8 {
    fn from(value: MessageKind) -> Self {
        match value {
            MessageKind::PlainText => 1,
        }
    }
}

impl TryFrom<u8> for MessageKind {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(MessageKind::PlainText),
            x => Err(x),
        }
    }
}

impl MlsApplicationMessage {
    pub fn build(content: Content, profile: &Profile) -> Self {
        let sender_server = profile.get_server().clone();
        let sender_account_id = profile.get_account_id();

        Self {
            client_stamp: DeliveryStamp::generate(),
            sender_server,
            sender_account_id,
            version: LicksMessageVersion::One,
            content,
        }
    }
}

impl Content {
    pub fn plain_text(body: String) -> Self {
        Self::BasicText { body }
    }
}
