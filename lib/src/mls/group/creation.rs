use std::time::SystemTime;

use crate::crypto::rng::random_bytes;
use crate::mls::crypto::credential::Credential;
use crate::mls::crypto::key_pair::SignatureKeyPair;
use crate::mls::crypto::provider::CryptoProvider;
use crate::mls::crypto::HPKEPrivateKey;
use crate::mls::extensibility::list::MlsExtension;
use crate::mls::framing::welcome::Welcome;
use crate::mls::framing::MlsGroupId;
use crate::mls::group::config::GroupConfig;
use crate::mls::group::Group;
use crate::mls::key_package::KeyPackage;
use crate::mls::key_schedule::InterimTranscriptHashInput;
use crate::mls::ratchet_tree::RatchetTree;
use crate::mls::utilities::error::{Error, Result};
use crate::mls::utilities::serde::Deserializer;
use bytes::Bytes;

use super::transcript::ConfirmedTranscriptHash;

impl Group {
    pub fn new(
        group_config: GroupConfig,
        credential: Credential,
        signature_key_pair: &SignatureKeyPair,
        group_id: Option<MlsGroupId>,
    ) -> Result<Self> {
        let group_id = if let Some(group_id) = group_id {
            group_id
        } else {
            let group_id = random_bytes::<16>().to_vec();
            Bytes::from(group_id)
        };

        let epoch = 0;
        let ratchet_tree = RatchetTree::default();
        let confirmed_transcript_hash = ConfirmedTranscriptHash::default();
        let extensions = Vec::new();

        Ok(Self {
            group_config,
            credential,
            signature_key: signature_key_pair.public_key.clone(),
            group_id,
            epoch,
            ratchet_tree,
            confirmed_transcript_hash,
            extensions,
        })
    }

    /// As described in `https://www.rfc-editor.org/rfc/rfc9420.html#name-joining-via-welcome-message`
    // Welcome is meant to be used once, so
    // we pass by value to destroy it
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_welcome(
        crypto_provider: &impl CryptoProvider,
        credential: Credential,
        group_config: GroupConfig,
        welcome: Welcome,
        ratchet_tree: RatchetTree,
    ) -> Result<Self> {
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-8.1
        let key_package = KeyPackage::deserialize_exact(
            &welcome
                .secrets()
                .iter()
                .find_map(|egs| crypto_provider.key_store().retrieve(egs.new_member()))
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;

        let key_package_ref = key_package.generate_ref(crypto_provider)?;
        crypto_provider.key_store().delete(&*key_package_ref);

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-8.1
        let init_priv_key = HPKEPrivateKey::deserialize_exact(
            &crypto_provider
                .key_store()
                .retrieve(&key_package.payload.init_key)
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-8.2
        let group_secrets =
            welcome.decrypt_group_secrets(crypto_provider, &key_package_ref, &init_priv_key)?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-10.1
        // No PSK support yet.

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-10.2
        let group_info =
            welcome.decrypt_group_info(crypto_provider, &group_secrets.joiner_secret, &[])?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.2
        // TODO: Verify `group_id` is unique, but we can't do that yet

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.4.1
        ratchet_tree.verify_integrity(
            crypto_provider,
            &group_info.group_context,
            SystemTime::now,
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.5
        let (my_leaf, is_identical) = ratchet_tree.find_leaf(&key_package.payload.leaf_node);
        debug_assert!(is_identical);

        let my_leaf_node = ratchet_tree
            .get_leaf(my_leaf)
            .expect("leaf exists because we just checked for its index");

        let private_key_of_my_leaf = my_leaf_node.payload.signature_key.clone();

        crypto_provider
            .key_store()
            .delete(&key_package.payload.init_key);

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.9
        group_info.verify_confirmation_tag(crypto_provider, &group_secrets.joiner_secret, &[])?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.10
        let interim_transcript = InterimTranscriptHashInput {
            confirmation_tag: group_info.confirmation_tag,
        };

        let cipher_suite = key_package.payload.cipher_suite;

        let group_context = group_info.group_context;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.3.1-12.10
        let interim_transcript_hash = interim_transcript.hash(
            crypto_provider,
            cipher_suite,
            &group_context.confirmed_transcript_hash,
        )?;

        let mut confirmed_transcript_hash = ConfirmedTranscriptHash::default();
        confirmed_transcript_hash.confirmed_hash = group_context.confirmed_transcript_hash;
        confirmed_transcript_hash.interim_hash = interim_transcript_hash;

        let extensions = group_context
            .extensions
            .extensions()
            .into_iter()
            .flat_map(|ext| MlsExtension::decode_extension(ext.clone()).ok())
            .collect();

        let group = Self {
            group_config,
            credential,
            signature_key: private_key_of_my_leaf,
            group_id: group_context.group_id,
            epoch: group_context.epoch,
            ratchet_tree,
            confirmed_transcript_hash,
            extensions,
        };

        Ok(group)
    }
}
