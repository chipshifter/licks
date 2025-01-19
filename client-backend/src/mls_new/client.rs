use anyhow::Result;
use lib::{
    identifiers::{GroupIdentifier, LicksIdentifier},
    mls::{
        crypto::{
            cipher_suite::CipherSuite,
            config::{CryptoConfig, CryptoConfigBuilder},
            credential::{Credential, Identity},
            key_pair::SignatureKeyPair,
            provider::RustCryptoProvider,
        },
        extensibility::Extensions,
        framing::{welcome::Welcome, MlsGroupId, ProtocolVersion},
        group::{config::GroupConfig, Group},
        key_package::{builder::KeyPackageBuilder, KeyPackage},
    },
};

pub struct LibMlsClient {
    crypto_provider: RustCryptoProvider,
    crypto_config: CryptoConfig,
    mls_credential: Credential,
    account_signature_key_pair: SignatureKeyPair,
    #[expect(dead_code)]
    supported_extensions: Extensions,
    group_config: GroupConfig,
}

impl LibMlsClient {
    /// Constructs the client from the given hardcoded ciphersuite.
    ///
    /// ``account_signature_key_pair``: Serialized [`SignatureKeyPair`]
    pub fn build(
        account_signature_key_pair: SignatureKeyPair,
        crypto_provider: RustCryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<Self> {
        let crypto_config = CryptoConfigBuilder::new()
            .with_cipher_suite(cipher_suite)
            .with_version(ProtocolVersion::MLS10)
            .build();

        let mls_credential =
            Credential::from_identity(Identity::new(b"change me to a better credential".to_vec()));

        let supported_extensions = Extensions::default();

        let group_config = GroupConfig::builder()
            .with_crypto_config(crypto_config)
            .build();

        Ok(Self {
            crypto_provider,
            crypto_config,
            mls_credential,
            account_signature_key_pair,
            supported_extensions,
            group_config,
        })
    }

    /// Generated a single [`KeyPackage`] which should then be
    /// sent to the server or a user, for inviting the client to a group.
    ///
    /// They are meant to be only used once.
    pub fn generate_key_package(&self) -> Result<KeyPackage> {
        let key_package = KeyPackageBuilder::new().build(
            &self.crypto_provider,
            self.crypto_config,
            self.mls_credential.clone(),
            &self.account_signature_key_pair,
        )?;

        Ok(key_package)
    }

    pub fn create_new_group(&self, group_id: GroupIdentifier) -> Result<Group> {
        let mls_group_id = MlsGroupId::from(group_id.to_bytes().to_vec());

        let group = Group::new(
            &self.crypto_provider,
            self.group_config.clone(),
            self.mls_credential.clone(),
            &self.account_signature_key_pair,
            Some(mls_group_id),
        )?;

        Ok(group)
    }

    pub fn join_group_from_welcome(&self, welcome: Welcome) -> Result<Group> {
        let group = Group::from_welcome(
            &self.crypto_provider,
            self.mls_credential.clone(),
            self.group_config.clone(),
            welcome,
        )?;

        Ok(group)
    }
}

#[cfg(test)]
mod tests {
    use lib::mls::crypto::provider::CryptoProvider;

    use super::*;

    #[test]
    fn simple_group_test() {
        const CIPHER_SUITE: CipherSuite = CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
        let alice_crypto_provider = RustCryptoProvider::default();

        let alice_key_pair = alice_crypto_provider
            .signature(CIPHER_SUITE)
            .expect("cipher suite is supported")
            .signature_key_pair()
            .expect("signature key pair generates");

        let alice_client = LibMlsClient::build(alice_key_pair, alice_crypto_provider, CIPHER_SUITE)
            .expect("client initializes");

        let bob_crypto_provider = RustCryptoProvider::default();

        let bob_key_pair = bob_crypto_provider
            .signature(CIPHER_SUITE)
            .expect("cipher suite is supported")
            .signature_key_pair()
            .expect("signature key pair generates");

        let bob_client = LibMlsClient::build(bob_key_pair, bob_crypto_provider, CIPHER_SUITE)
            .expect("client initializes");

        // Alice creates Group, generates a Welcome message for Bob, Bob joins group using Welcome

        let bob_key_package = bob_client
            .generate_key_package()
            .expect("key package is generated");

        let group_id = GroupIdentifier::generate_id();

        let alice_group = alice_client
            .create_new_group(group_id)
            .expect("group creates");

        let alice_welcome = alice_group
            .create_welcome(bob_key_package, &alice_client.crypto_provider)
            .expect("alice can create a welcome for bob");

        let bob_group = bob_client
            .join_group_from_welcome(alice_welcome)
            .expect("bob imports alice's group state successfully");

        assert_eq!(alice_group, bob_group);
    }
}
