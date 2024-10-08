#![allow(warnings)]
use crate::mls::{
    crypto::{provider::CryptoProvider, HPKEPublicKey},
    framing::{group_info::GroupInfo, welcome::Welcome},
    key_package::{KeyPackage, KeyPackageRef},
    key_schedule::GroupContext,
    utilities::error::Result,
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
}
