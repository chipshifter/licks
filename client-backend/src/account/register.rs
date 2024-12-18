use crate::manager::{account::Profile, WEBSOCKET_MANAGER};
use anyhow::{bail, Context, Result};
use lib::{
    api::{
        connection::{Message, UnauthRequest},
        registration::{RegistrationService, Stage1Message, Stage3Message},
        server::Server,
    },
    crypto::{
        certificates::{
            ed25519::{Ed25519AccountCert, Ed25519CertificateChainSecret, Ed25519DeviceCert},
            CertificateChainSecret,
        },
        usernames::UsernameHash,
    },
    identifiers::{DeviceId, LicksIdentifier},
};

pub async fn create_account(server: &Server, username_hash: UsernameHash) -> Result<Profile> {
    let (account_public, mut account_secret) = Ed25519AccountCert::generate_keys();

    // Stage 1 request
    let req = UnauthRequest::Registration(RegistrationService::Stage1(
        Stage1Message::HereIsMyAccountPublicKey(account_public.to_bytes().to_vec()),
    ));

    let assigned_account_id = match WEBSOCKET_MANAGER.request_unauth(server, req).await? {
        Message::Unauth(UnauthRequest::Registration(RegistrationService::Stage1(
            Stage1Message::HereIsYourAccountId(account_id),
        ))) => Some(account_id),
        other => {
            log::error!("Stage 1 failed, received an unexpected response: {other:?}");
            None
        }
    }
    .context("Registration's first stage failed")?;

    // Create account certificate
    let account_cert = Ed25519AccountCert::complete(
        account_public,
        &mut account_secret,
        server.to_owned(),
        assigned_account_id,
    );

    let account_cert_serialized = account_cert.clone().serialize();

    // Stage 2 request
    let req = UnauthRequest::Registration(RegistrationService::Stage2(account_cert_serialized));

    match WEBSOCKET_MANAGER.request_unauth(server, req).await? {
        Message::Ok => {
            log::info!("Stage 2 registration success");
        }
        other => {
            log::error!("Stage 2 failed, received this response: {other:?}");
            bail!("Registration failed at stage 2.");
        }
    }

    // Stage 3: Generate device certificate, create certificate chain, send it to server
    let device_id = DeviceId::generate_id();
    let (device_cert, device_secret) = Ed25519DeviceCert::generate(device_id);

    let certificate_chain_secret = Ed25519CertificateChainSecret::new(
        account_cert,
        account_secret,
        device_cert,
        device_secret,
    );

    let certificate_chain_public = certificate_chain_secret.serialized();

    let req = UnauthRequest::Registration(RegistrationService::Stage3(Stage3Message {
        certificate: certificate_chain_public,
        username_hash,
    }));

    match WEBSOCKET_MANAGER.request_unauth(server, req).await? {
        Message::Ok => {
            log::info!("Stage 3 registration success");
            let profile: Profile = Profile::V1(certificate_chain_secret);

            Ok(profile)
        }
        other => {
            log::error!("Stage 3 failed, received this response: {other:?}");
            bail!("Registration failed at stage 3: {other:?}.");
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::crypto::usernames::Username;

    use super::*;

    #[tokio::test]
    async fn test_basic_client_registration() {
        let server = Server::localhost();

        create_account(
            &server,
            Username::new("test_registation".to_string())
                .expect("username is valid")
                .hash(),
        )
        .await
        .expect("Registration works");
    }
}
