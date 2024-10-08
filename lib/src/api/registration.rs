//! Registration on an unauthenticated channel
//!
//! Stage 1: Generate `AccountId`
//! - Client sends to the server the account public key
//! - Server stores it temporarily for step 2, assigns an `AccountId` to it
//!
//! Stage 2: Create `AccountCertificate`
//! - The client can now create the `AccountCertificate`, and sends it
//!   to the server (the certificate will self-sign and sign the `AccountId`)
//! - The server verifies the credential and stores it if valid.
//!
//! Stage 3: Create the first `DeviceCertificate`
//! - Client generates a `DeviceCertificate` on their own.
//!   They then create the `CertificateChain` and sends that to the server.
//! - The server checks the chain is valid (using their verified `AccountCertificate`)
//!   If the chain is valid, it validates the certificate chain and keeps it:
//!   the server will have a `AccountId` -> Vec<CertificateChain> kind of database.
//!
//! After that, the authenticated channel can be used.

use serde::{Deserialize, Serialize};

use crate::{
    crypto::{
        certificates::{SerializedAccountCertificate, SerializedChain},
        usernames::UsernameHash,
    },
    error::ProtoError,
    identifiers::AccountId,
};

use super::connection::{
    proto::{self},
    ServiceMessage,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RegistrationService {
    Stage1(Stage1Message),
    Stage2(SerializedAccountCertificate),
    Stage3(Stage3Message),
}

impl ServiceMessage for RegistrationService {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Stage1Message {
    HereIsMyAccountPublicKey(Vec<u8>),
    HereIsYourAccountId(AccountId),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stage3Message {
    pub certificate: SerializedChain,
    pub username_hash: UsernameHash,
}

impl From<RegistrationService> for proto::registration_service::Stage {
    fn from(value: RegistrationService) -> Self {
        match value {
            RegistrationService::Stage1(req) => {
                proto::registration_service::Stage::StageOne(req.into())
            }
            RegistrationService::Stage2(req) => {
                proto::registration_service::Stage::StageTwo(req.into())
            }
            RegistrationService::Stage3(req) => {
                proto::registration_service::Stage::StageThree(req.into())
            }
        }
    }
}

impl From<Stage1Message> for proto::Stage1 {
    fn from(value: Stage1Message) -> Self {
        let inner: proto::stage1::Inner = match value {
            Stage1Message::HereIsMyAccountPublicKey(pub_key) => {
                proto::stage1::Inner::HereIsMyAccountPublicKey(pub_key)
            }
            Stage1Message::HereIsYourAccountId(account_id) => {
                proto::stage1::Inner::HereIsYourAccountId(account_id.into())
            }
        };

        Self { inner: Some(inner) }
    }
}

impl From<SerializedAccountCertificate> for proto::Stage2 {
    fn from(value: SerializedAccountCertificate) -> Self {
        proto::Stage2 {
            here_is_my_account_certificate: Some(value.into()),
        }
    }
}

impl From<Stage3Message> for proto::Stage3 {
    fn from(value: Stage3Message) -> Self {
        proto::Stage3 {
            here_is_my_certificate_chain: Some(value.certificate.into()),
            username: value.username_hash.0.to_vec(),
        }
    }
}

impl TryFrom<proto::stage1::Inner> for Stage1Message {
    type Error = ProtoError;

    fn try_from(value: proto::stage1::Inner) -> Result<Self, Self::Error> {
        Ok(match value {
            proto::stage1::Inner::HereIsMyAccountPublicKey(pub_key) => {
                Self::HereIsMyAccountPublicKey(pub_key)
            }
            proto::stage1::Inner::HereIsYourAccountId(acc_id) => {
                Self::HereIsYourAccountId(acc_id.try_into()?)
            }
        })
    }
}

impl TryFrom<proto::Stage2> for SerializedAccountCertificate {
    type Error = ProtoError;

    fn try_from(value: proto::Stage2) -> Result<Self, Self::Error> {
        value
            .here_is_my_account_certificate
            .ok_or(ProtoError)?
            .try_into()
            .map_err(|_| ProtoError)
    }
}

impl TryFrom<proto::Stage3> for Stage3Message {
    type Error = ProtoError;

    fn try_from(value: proto::Stage3) -> Result<Self, Self::Error> {
        let certificate = value
            .here_is_my_certificate_chain
            .ok_or(ProtoError)?
            .try_into()
            .map_err(|_| ProtoError)?;

        let username: [u8; 32] = value.username.try_into().map_err(|_| ProtoError)?;
        let username = UsernameHash(username);

        Ok(Self {
            certificate,
            username_hash: username,
        })
    }
}
