use std::time::SystemTime;

use crate::crypto::rng::random_bytes;
use crate::mls;
use crate::mls::crypto::credential::{Credential, CredentialType};
use crate::mls::crypto::key_pair::{EncryptionKeyPair, SignatureKeyPair};
use crate::mls::crypto::provider::CryptoProvider;
use crate::mls::crypto::{HPKEPrivateKey, Key};
use crate::mls::extensibility::list::MlsExtension;
use crate::mls::extensibility::{ExtensionType, Extensions};
use crate::mls::framing::welcome::Welcome;
use crate::mls::framing::{MlsGroupId, ProtocolVersion};
use crate::mls::group::config::GroupConfig;
use crate::mls::group::Group;
use crate::mls::key_package::KeyPackage;
use crate::mls::key_schedule::InterimTranscriptHashInput;
use crate::mls::ratchet_tree::leaf_node::{
    Capabilities, LeafNode, LeafNodeSource, TreeInfoTBS, TreePosition,
};
use crate::mls::ratchet_tree::{Node, RatchetTree};
use crate::mls::utilities::error::{Error, Result};
use crate::mls::utilities::serde::Deserializer;
use crate::mls::utilities::tree_math::LeafIndex;
use bytes::Bytes;

use super::transcript::ConfirmedTranscriptHash;

impl Group {
    pub fn new(
        crypto_provider: &impl CryptoProvider,
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

        let mls_extensions: Vec<MlsExtension> = Vec::new();
        let extensions: Vec<mls::extensibility::Extension> = mls_extensions
            .clone()
            .iter()
            .flat_map(|mls_ext| mls_ext.encode_extension().ok())
            .collect();
        let extensions_types: Vec<ExtensionType> = extensions
            .clone()
            .iter()
            .map(|ext| ext.extension_type)
            .collect();

        let capabilities = Capabilities {
            versions: vec![ProtocolVersion::MLS10],
            cipher_suites: crypto_provider.supported(),
            extensions: extensions_types,
            proposals: vec![],
            credentials: vec![CredentialType::Basic],
        };

        let tree_info_tbs = TreeInfoTBS::UpdateOrCommit(TreePosition {
            group_id: group_id.clone(),
            leaf_index: LeafIndex::new(0), // root of tree
        });

        // A tree with a single node, a leaf node containing an HPKE public key and credential for the creator
        let (leaf_node, encryption_key_pair) = LeafNode::new(
            crypto_provider,
            group_config.crypto_config,
            credential.clone(),
            &signature_key_pair.clone(),
            LeafNodeSource::Update,
            capabilities,
            Extensions::new(extensions),
            tree_info_tbs,
        )?;

        let mut ratchet_tree = RatchetTree::default();
        ratchet_tree.0.push(Some(Node::Leaf(leaf_node.clone())));

        let confirmed_transcript_hash = ConfirmedTranscriptHash::default();

        Ok(Self {
            group_config,
            credential,
            encryption_key_pair,
            signature_key: signature_key_pair.public_key.clone(),
            group_id,
            epoch,
            ratchet_tree,
            confirmed_transcript_hash,
            extensions: mls_extensions,
            our_leaf_node: leaf_node,
            our_generation: 0,
            init_secret: Key::default(),
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

        let ratchet_tree = RatchetTree::deserialize_exact(
            group_info
                .extensions
                .find_extension_data(ExtensionType::RatchetTree)
                .ok_or(Error::NoRatchetTreeInGroup)?,
        )?;

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

        let public_encryption_key = my_leaf_node.payload.encryption_key.clone();
        let encryption_key_pair = EncryptionKeyPair::deserialize_exact(
            crypto_provider
                .key_store()
                .retrieve(&public_encryption_key)
                .ok_or(Error::InvalidLeafNode)?,
        )?;

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
            encryption_key_pair,
            signature_key: private_key_of_my_leaf,
            group_id: group_context.group_id,
            epoch: group_context.epoch,
            ratchet_tree,
            confirmed_transcript_hash,
            extensions,
            our_leaf_node: key_package.payload.leaf_node,
            init_secret: Key::default(),
            our_generation: 0,
        };

        Ok(group)
    }
}
