use lib::{
    api::server::Server,
    crypto::certificates::ed25519::{
        Ed25519AccountCert, Ed25519CertificateChainSecret, Ed25519DeviceCert,
    },
    identifiers::{AccountId, DeviceId, LicksIdentifier},
};

use crate::manager::account::Profile;

pub fn fake_profile(server: Server) -> Profile {
    let fake_chain = {
        let (account_cert, account_secret) =
            Ed25519AccountCert::generate(server, AccountId::generate_id());

        let (device_cert, device_secret) = Ed25519DeviceCert::generate(DeviceId::generate_id());

        Ed25519CertificateChainSecret::new(account_cert, account_secret, device_cert, device_secret)
    };

    Profile::V1(fake_chain)
}
