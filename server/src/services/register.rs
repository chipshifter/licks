use std::{sync::LazyLock, time::SystemTime};

use lib::{
    api::{
        connection::{Message, ServiceError, ServiceResult, UnauthRequest},
        registration::{self, Stage1Message, Stage3Message},
    },
    crypto::certificates::{Certificate, CertificateChain, SerializedAccountCertificate},
    identifiers::{AccountId, LicksIdentifier},
};
use serde::{Deserialize, Serialize};
use sled::Tree;

use crate::{
    accounts::AccountService,
    connection::ConnectionService,
    db::{deserialize_bytes, serialize_bytes, DB},
};

use super::usernames::UsernameService;

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    #[error("Verification failed because the given AccountId doesn't exist.")]
    AccountDoesNotExist,
    #[error("Verification failed because the given AccountId is incorrect.")]
    VerificationAccoundIdError,
    #[error("Verification failed because the signature is incorrect.")]
    VerificationSignatureError,
    #[error("Verification failed because an account with this AccountId already exists!")]
    AccountAlreadyExists,
}

// Temporarily allocated AccountIds for new users.
// Users in this database are expected to upload their AccountCertificate
// generated with the AccountId they were given.
pub static STAGE_ONE: LazyLock<Tree> = LazyLock::new(|| {
    DB.open_tree(b"accounts/stage1")
        .expect("sled is open and works")
});

// AccountCertificates that have been validated, but that haven't had a
// DeviceCertificate added to yet. We store the protobuf bytes directly
pub static STAGE_TWO: LazyLock<Tree> = LazyLock::new(|| {
    DB.open_tree(b"accounts/stage2")
        .expect("sled is open and works")
});

#[derive(Debug, Serialize, Deserialize)]
pub struct UnverifiedAccountEntry {
    pub timestamp: SystemTime,
    pub account_pub_key: Vec<u8>,
}

pub struct RegistrationService {}

#[allow(clippy::match_wildcard_for_single_variants)]
impl ConnectionService<registration::RegistrationService> for RegistrationService {
    async fn handle_request(
        request: &mut impl crate::connection::RequestHandler,
        msg: registration::RegistrationService,
    ) -> Result<(), crate::error::Error> {
        match msg {
            registration::RegistrationService::Stage1(req) => match req {
                Stage1Message::HereIsMyAccountPublicKey(pub_key) => {
                    request.map_service_result(Self::stage_1, pub_key).await
                }
                _ => request.error(ServiceError::InvalidOperation).await,
            },
            registration::RegistrationService::Stage2(req) => {
                request.map_service_result(Self::stage_2, req).await
            }
            registration::RegistrationService::Stage3(req) => {
                request.map_service_result(Self::stage_3, req).await
            }
        }
    }
}

impl RegistrationService {
    pub fn stage_1(pub_key: Vec<u8>) -> ServiceResult {
        // This allocates an AccountId to a user, but
        // registration is not complete yet.
        let mut account_id = AccountId::generate_id();

        // Check if account is already registered,
        // if so, continue generating random AccountIds.
        while AccountService::is_account_registered(&account_id)? {
            account_id = AccountId::generate_id();
        }

        tracing::debug!("Assigning AccountId {account_id} to user with public key {pub_key:X?}");
        let entry = UnverifiedAccountEntry {
            timestamp: SystemTime::now(),
            account_pub_key: pub_key,
        };

        let entry_bytes = serialize_bytes(entry)?;

        let _insert = STAGE_ONE
            .insert(account_id, entry_bytes)
            .map_err(|_| ServiceError::InternalError)?;

        Ok(Message::Unauth(UnauthRequest::Registration(
            registration::RegistrationService::Stage1(Stage1Message::HereIsYourAccountId(
                account_id,
            )),
        )))
    }

    pub fn stage_2(account_certificate: SerializedAccountCertificate) -> ServiceResult {
        // Verify the account certificate
        // Check 1. Is it self-signed using the public key we got?
        // Check 2. Is the AccountId correct?
        // TODO 3. Is the server domain correct?
        let (account_certificate, account_id) = account_certificate
            .verify()
            .map_err(|_| ServiceError::InvalidCredentials)?;

        match STAGE_ONE
            .get(account_id)
            .map_err(|_| ServiceError::InternalError)?
        {
            Some(unverified_account_entry) => {
                // Verify signature
                let unverified_account_entry: UnverifiedAccountEntry =
                    deserialize_bytes(unverified_account_entry)?;
                let account_pub_key = unverified_account_entry.account_pub_key;

                if account_certificate.pub_key_bytes() == account_pub_key {
                    // Check 1 and 2 is OK

                    // Insert account certificate in stage two tree,
                    // waiting for the user to generate a full certificate chain...
                    STAGE_TWO
                        .insert(account_id, account_certificate.to_bytes())
                        .map_err(|_| ServiceError::InternalError)?;

                    Ok(Message::Ok)
                } else {
                    Err(ServiceError::InvalidCredentials)
                }
            }
            None => Err(ServiceError::InvalidRequest),
        }
    }

    pub fn stage_3(req: Stage3Message) -> ServiceResult {
        let Stage3Message {
            certificate: serialized_chain,
            username_hash: username,
        } = req;

        let account_id = serialized_chain.account_id();

        match STAGE_TWO
            .get(account_id)
            .map_err(|_| ServiceError::InternalError)?
        {
            Some(stage_2_acc_cert_bytes) => {
                let (stage_2_account_cert, account_id) =
                    SerializedAccountCertificate::from_bytes(&stage_2_acc_cert_bytes)
                        .map_err(|_| ServiceError::DecodeError)?
                        .verify()
                        .map_err(|_| ServiceError::InvalidCredentials)?;

                // - Does the chain include the AccountCertificate we were given
                // - Is the chain valid
                let chain = serialized_chain
                    .clone()
                    .verify()
                    .map_err(|_| ServiceError::InvalidCredentials)?;

                if chain
                    .account_cert()
                    .to_bytes()
                    .eq(&stage_2_account_cert.to_bytes())
                {
                    UsernameService::set_username(&account_id, username)?;
                    AccountService::register_account(serialized_chain, username)?;

                    Ok(Message::Ok)
                } else {
                    Err(ServiceError::InvalidCredentials)
                }
            }
            None => Err(ServiceError::InvalidOperation),
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::{
        api::server::Server,
        crypto::{
            certificates::{
                ed25519::{Ed25519AccountCert, Ed25519CertificateChainSecret, Ed25519DeviceCert},
                CertificateChainSecret,
            },
            usernames::Username,
        },
        identifiers::DeviceId,
    };

    use super::*;

    #[test]
    fn test_full_registration() {
        // Generate
        let (account_pub_key, mut account_secret) = Ed25519AccountCert::generate_keys();

        // Stage 1
        let res = RegistrationService::stage_1(account_pub_key.to_bytes().to_vec())
            .expect("Stage 1 is ok");

        let Message::Unauth(UnauthRequest::Registration(
            registration::RegistrationService::Stage1(Stage1Message::HereIsYourAccountId(
                account_id,
            )),
        )) = res
        else {
            panic!("Unexpected response from server")
        };

        // generate certificate
        let account_cert = Ed25519AccountCert::complete(
            account_pub_key,
            &mut account_secret,
            Server::localhost(),
            account_id,
        );

        // Stage 2
        let res =
            RegistrationService::stage_2(account_cert.clone().serialize()).expect("Stage 2 is ok");

        assert_eq!(res, Message::Ok);

        // Stage 3

        // generate device certificate
        let device_id = DeviceId::generate_id();
        let (device_cert, device_secret) = Ed25519DeviceCert::generate(device_id);

        // generate certificate chain
        let cert_chain_secret = Ed25519CertificateChainSecret::new(
            account_cert,
            account_secret,
            device_cert,
            device_secret,
        );

        let cert_chain_public = cert_chain_secret.serialized();

        let res = RegistrationService::stage_3(Stage3Message {
            certificate: cert_chain_public,
            username_hash: Username::new("test".to_string())
                .expect("username is valid")
                .hash(),
        })
        .expect("Stage 3 is ok");

        assert_eq!(res, Message::Ok);
    }

    #[test]
    fn test_bad_registrations() {
        todo!("Rewrite bad registration test with newer certs");
    }
}
