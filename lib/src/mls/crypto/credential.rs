//! [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Each member of a group
//! presents a credential that provides one or more identities for the member and associates them
//! with the member's signing key.

use bytes::{Buf, BufMut, Bytes};
use std::ops::Deref;

use crate::mls::utilities::{
    error::{Error, Result},
    serde::{deserialize_opaque_vec, serialize_opaque_vec, Deserializer, Serializer},
};

/// [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Enum type of Credential
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum CredentialType {
    #[default]
    /// A "basic" credential type
    Basic = 0x0001,
    Unknown(u16),
}

impl From<u16> for CredentialType {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => CredentialType::Basic,
            _ => CredentialType::Unknown(v),
        }
    }
}

impl From<CredentialType> for u16 {
    fn from(val: CredentialType) -> u16 {
        match val {
            CredentialType::Basic => 0x0001,
            CredentialType::Unknown(v) => v,
        }
    }
}

/// a bare assertion of an identity, without any additional information
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Identity(Bytes);

impl Identity {
    /// Creates a new Identity
    pub fn new<T: Into<Bytes>>(identify: T) -> Self {
        Self(identify.into())
    }
}

impl Deref for Identity {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for Identity {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(Identity(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for Identity {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}

/// Certificate contains a X.509 certificate
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Certificate {
    cert_data: Bytes,
}

impl Certificate {
    /// Creates a X.509 certificate
    pub fn new(cert_data: Bytes) -> Self {
        Self { cert_data }
    }
}

impl Deserializer for Certificate {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(Self {
            cert_data: deserialize_opaque_vec(buf)?,
        })
    }
}

impl Serializer for Certificate {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.cert_data, buf)
    }
}

/// [RFC9420 Sec.5.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.3) Credential provides
/// "presented identifiers"
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Credential {
    /// A "basic" credential is a bare assertion of an identity, without any additional information.
    /// The format of the encoded identity is defined by the application.
    Basic(Identity),
}

impl Default for Credential {
    fn default() -> Self {
        Self::Basic(Identity::default())
    }
}

impl Credential {
    /// Create a Credential from identify
    pub fn from_identity(identity: Identity) -> Self {
        Self::Basic(identity)
    }

    /// Returns the identity of a given credential if it is basic type
    pub fn identity(&self) -> Option<&Identity> {
        let Credential::Basic(identity) = self;

        Some(identity)
    }
}

impl Deserializer for Credential {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let credential_type = buf.get_u16().into();

        match credential_type {
            CredentialType::Basic => Ok(Self::Basic(Identity::deserialize(buf)?)),
            CredentialType::Unknown(_) => Err(Error::InvalidCredentialTypeValue),
        }
    }
}

impl Serializer for Credential {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.credential_type().into());
        match self {
            Credential::Basic(identity) => identity.serialize(buf),
        }
    }
}

impl Credential {
    pub fn credential_type(&self) -> CredentialType {
        match self {
            Credential::Basic(_) => CredentialType::Basic,
        }
    }
}
