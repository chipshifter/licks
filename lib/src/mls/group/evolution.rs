#![allow(warnings)]
use crate::mls::{
    crypto::{provider::CryptoProvider, HPKEPublicKey},
    framing::{
        group_info::{GroupInfo, GroupSecrets},
        welcome::{EncryptedGroupSecrets, Welcome},
    },
    key_package::{KeyPackage, KeyPackageRef},
    key_schedule::{extract_welcome_secret, GroupContext},
    ratchet_tree::HPKECiphertext,
    utilities::{error::Result, serde::Serializer},
};

use super::Group;

impl Group {
    pub fn get_group_context(&self, crypto_provider: &impl CryptoProvider) -> Result<GroupContext> {
        let version = self.group_config.crypto_config.version;
        let cipher_suite = self.group_config.crypto_config.cipher_suite;
        let group_id = self.group_id.clone();
        let epoch = self.epoch;
        let tree_hash = self
            .ratchet_tree
            .compute_root_tree_hash(crypto_provider, cipher_suite)?;
        let extensions = self.group_config.extensions.clone();
        let confirmed_transcript_hash = self.confirmed_transcript_hash.confirmed_hash.clone();

        Ok(GroupContext {
            version,
            cipher_suite,
            group_id,
            epoch,
            tree_hash,
            confirmed_transcript_hash,
            extensions,
        })
    }

    pub fn create_welcome(
        &self,
        key_package: KeyPackage,
        crypto_provider: &impl CryptoProvider,
    ) -> Result<Welcome> {
        // TODO: This might all need to be moved in a `create_commit` function,
        // which in the case of creating a welcome, would both create a Welcome
        // and a new user commit at the same time

        let key_package_ref = key_package.generate_ref(crypto_provider)?;
        let cipher_suite = key_package.payload.cipher_suite;

        let group_context = self.get_group_context(crypto_provider)?;

        // TODO support PSKs?
        let psk_secret = &[];

        let joiner_secret = group_context.extract_joiner_secret(
            crypto_provider,
            todo!("path secrets / init_secret[n-1]"),
            todo!("commit secret from current epoch"),
        )?;

        let welcome_secret =
            extract_welcome_secret(crypto_provider, cipher_suite, &joiner_secret, psk_secret)?;

        let (welcome_key, welcome_nonce) =
            Welcome::extract_key_and_nonce(welcome_secret, crypto_provider, cipher_suite)?;

        let group_info: GroupInfo = todo!("Create GroupInfoTBS struct, and sign it");
        let group_info_serialized = group_info.serialize_detached()?;

        // AEAD seal serialized group info with welcome key+nonce
        let encrypted_group_info = crypto_provider.hpke(cipher_suite)?.aead_seal(
            &welcome_key,
            &welcome_nonce,
            &group_info_serialized,
            &[], /* no additional data */
        )?;

        let group_secrets = GroupSecrets {
            joiner_secret,
            path_secret: todo!("path secrets"),
            psk_ids: vec![],
        };

        let group_secrets_bytes = group_secrets.serialize_detached()?;

        let (kem_output, ciphertext) = crypto_provider.encrypt_with_label(
            cipher_suite,
            &key_package.payload.init_key,
            b"Welcome",
            &encrypted_group_info,
            &group_secrets_bytes,
        )?;

        // TODO: This is just one secret, should we do more? How?
        let encrypted_group_secrets = EncryptedGroupSecrets::new(
            key_package_ref,
            HPKECiphertext {
                kem_output,
                ciphertext,
            },
        );

        Ok(Welcome {
            cipher_suite,
            secrets: vec![encrypted_group_secrets],
            encrypted_group_info,
        })
    }
}
