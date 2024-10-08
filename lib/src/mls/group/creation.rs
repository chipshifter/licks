use crate::crypto::rng::random_bytes;
use crate::mls::crypto::credential::Credential;
use crate::mls::crypto::key_pair::SignatureKeyPair;
use crate::mls::crypto::provider::CryptoProvider;
use crate::mls::framing::welcome::Welcome;
use crate::mls::framing::MlsGroupId;
use crate::mls::group::config::GroupConfig;
use crate::mls::group::Group;
use crate::mls::key_package::KeyPackage;
use crate::mls::ratchet_tree::RatchetTree;
use crate::mls::utilities::error::{Error, Result};
use crate::mls::utilities::serde::Deserializer;

use crate::mls::crypto::{HPKEPrivateKey, Key};
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

    // Welcome is meant to be used once, so
    // we pass by value to destroy it
    #[allow(clippy::needless_pass_by_value)]
    pub fn from_welcome(
        crypto_provider: &impl CryptoProvider,
        _group_config: GroupConfig,
        welcome: Welcome,
        _ratchet_tree: Option<RatchetTree>,
    ) -> Result<Self> {
        let key_package = KeyPackage::deserialize_exact(
            &welcome
                .secrets()
                .iter()
                .find_map(|egs| crypto_provider.key_store().retrieve(egs.new_member()))
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;
        crypto_provider
            .key_store()
            .delete(&*key_package.generate_ref(crypto_provider)?);

        let _private_key: HPKEPrivateKey = Key::deserialize_exact(
            &crypto_provider
                .key_store()
                .retrieve(&key_package.payload.init_key)
                .ok_or(Error::NoMatchingKeyPackage)?,
        )?;
        crypto_provider
            .key_store()
            .delete(&key_package.payload.init_key);

        Ok(Self::default())
    }
}
