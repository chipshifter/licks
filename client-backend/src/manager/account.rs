use std::hash::Hash;

use anyhow::bail;
use lib::{
    api::{
        connection::{Message, UnauthRequest},
        server::Server,
    },
    crypto::{
        certificates::{
            ed25519::Ed25519CertificateChainSecret, CertificateChain, CertificateChainSecret,
        },
        challenge::{AuthChallenge, AuthChallengeResponse},
    },
    error::ProtoError,
    identifiers::{AccountId, DeviceId},
};

pub use lib::crypto::usernames::{Username, UsernameHash};

use super::{ProfileManager, CONNECTIONS_MANAGER};
use crate::mls::credentials::LicksMlsCredential;
use mls_rs::identity::SigningIdentity;

/// `Profile` (meaning `CertificateChainSecret`) holds:
/// - `AccountId`
/// - Server domain of account
/// - `DeviceId`
/// - The public and secret keys for the account and device
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum Profile {
    V1(Ed25519CertificateChainSecret),
}

impl Profile {
    pub fn get_server(&self) -> &Server {
        match self {
            Profile::V1(cert_secret) => cert_secret.public_chain.get_server(),
        }
    }

    pub fn mls_credential_public(&self) -> LicksMlsCredential {
        match self {
            Profile::V1(cert_secret) => LicksMlsCredential {
                chain: cert_secret.serialized(),
            },
        }
    }

    pub fn get_account_id(&self) -> AccountId {
        match self {
            Profile::V1(cert_secret) => *cert_secret.public_chain.account_id(),
        }
    }

    pub fn get_device_id(&self) -> DeviceId {
        match self {
            Profile::V1(cert_secret) => *cert_secret.public_chain.device_id(),
        }
    }

    pub fn to_mls_signer(&self) -> (Vec<u8>, SigningIdentity) {
        (
            self.get_device_secret_key().to_vec(),
            self.mls_credential_public().into(),
        )
    }

    pub fn get_auth_challenge_response(&self, challenge: AuthChallenge) -> AuthChallengeResponse {
        match self {
            Profile::V1(cert_secret) => challenge.accept(cert_secret),
        }
    }

    pub fn get_device_secret_key(&self) -> [u8; 64] {
        match self {
            // `.as_bytes()` returns just the compressed secret key bytes
            // but mls-rs expects the full uncompressed representation, so use `.to_keypair_bytes()`
            Profile::V1(cert_secret) => cert_secret.device_secret.to_keypair_bytes(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Profile::V1(cert_secret) => cert_secret.to_bytes(),
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        Ok(Profile::V1(Ed25519CertificateChainSecret::from_bytes(
            bytes,
        )?))
    }
}

impl ProfileManager {
    pub async fn find_account_id_by_username(
        &self,
        username: Username,
    ) -> anyhow::Result<Option<AccountId>> {
        let resp = CONNECTIONS_MANAGER
            .request_unauthenticated(
                self.get_server(),
                UnauthRequest::GetAccountFromUsername(username.hash()),
            )
            .await?;

        match resp {
            Message::Unauth(UnauthRequest::HereIsAccount(account_id)) => Ok(Some(account_id)),
            Message::Unauth(UnauthRequest::NoAccount) => Ok(None),
            err => {
                log::error!("Unexpected response while looking up username: {err:?}");
                bail!("Unexpected response while looking up username: {err:?}");
            }
        }
    }
}
