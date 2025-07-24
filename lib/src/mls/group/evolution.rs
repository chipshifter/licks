#![allow(warnings)]
use std::{collections::HashSet, ops::Add};

use bytes::Bytes;

use crate::mls::{
    crypto::{
        cipher_suite::{self, CipherSuite},
        provider::CryptoProvider,
        HPKEPublicKey, Key,
    },
    extensibility::{list::MlsExtension, RatchetTreeExtension},
    framing::{
        commit::Commit,
        group_info::{GroupInfo, GroupSecrets},
        private_message::PrivateMessage,
        proposal::{AddProposal, Proposal, ProposalOrRef, ReInitProposal},
        welcome::{EncryptedGroupSecrets, Welcome},
        Content, FramedContent, FramedContentTBS, ProtocolVersion, Sender, SenderData, WireFormat,
    },
    group::transcript::ConfirmedTranscriptHash,
    key_package::{KeyPackage, KeyPackageRef},
    key_schedule::{
        extract_welcome_secret, ConfirmedTranscriptHashInput, GroupContext,
        InterimTranscriptHashInput, SECRET_LABEL_CONFIRM, SECRET_LABEL_ENCRYPTION,
        SECRET_LABEL_SENDER_DATA,
    },
    ratchet_tree::{
        leaf_node::LeafNode, parent_node::ParentNode, HPKECiphertext, Node, UpdatePath,
        UpdatePathNode,
    },
    secret_tree::{RatchetLabel, SecretTree},
    utilities::{
        error::{Error, Result},
        serde::Serializer,
        tree_math::{LeafIndex, NodeIndex},
    },
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
        // todo: not this
        let extensions = vec![MlsExtension::RatchetTree(RatchetTreeExtension::new(
            self.ratchet_tree.clone(),
        ))]
        .try_into()?;
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

    pub fn create_commit(
        &mut self,
        proposals: Vec<Proposal>,
        crypto_provider: &impl CryptoProvider,
        new_members_key_packages: Option<Vec<KeyPackage>>,
    ) -> Result<(PrivateMessage, Welcome)> {
        let cipher_suite = self.group_config.crypto_config.cipher_suite;
        let mut new_group = self.clone();
        // todo verify proposals
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.1

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.2
        let mut commit = Commit {
            path: None,
            proposals: proposals
                .clone()
                .into_iter()
                .map(|prop| ProposalOrRef::Proposal(prop))
                .collect(),
        };

        let mut external_init_kem_output: Option<Bytes> = None;
        let mut reinit_proposal: Option<ReInitProposal> = None;

        // Apply proposal list
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.3

        // https://www.rfc-editor.org/rfc/rfc9420.html#applying-a-proposal-list
        // All the for-s are to preserve order of processing in a lazy way
        // TODO: This can definitely be optimized

        for proposal in &proposals {
            if let Proposal::GroupContextExtensions(exts_proposal) = proposal {
                new_group.extensions = exts_proposal.extensions.clone().try_into().unwrap();
            }
        }

        let (sender_index, leaf_exists) = new_group.ratchet_tree.find_leaf(&self.our_leaf_node);

        // Apply Update/Add/Remove
        new_group.ratchet_tree.apply(&proposals, &[sender_index]);

        for proposal in &proposals {
            if let Proposal::ExternalInit(init_proposal) = proposal {
                external_init_kem_output = Some(init_proposal.kem_output.clone());
            }
        }

        for proposal in &proposals {
            if let Proposal::ReInit(p) = proposal {
                reinit_proposal = Some(p.clone());
            }
        }

        // Update epoch
        new_group.epoch += 1;

        // Populate commit's `path` field
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.1

        // TODO
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.1
        let (sender_index, leaf_exists) = new_group.ratchet_tree.find_leaf(&self.our_leaf_node);
        let path_secret = new_group.ratchet_tree.update_direct_path(
            crypto_provider,
            cipher_suite,
            sender_index,
            self.signature_key_pair.private_key(),
            new_group.group_id.clone(),
        )?;

        let filtered_direct_path = new_group
            .ratchet_tree
            .filtered_direct_path(sender_index.node_index())?;

        let parent_nodes: Vec<ParentNode> = filtered_direct_path
            .iter()
            .filter_map(|node| {
                if let Some(Node::Parent(parent)) = new_group.ratchet_tree.get(*node) {
                    Some(parent.clone())
                } else {
                    None
                }
            })
            .collect();

        let commit_secret = crypto_provider.derive_secret(cipher_suite, &path_secret, b"path")?;

        let old_group_context = self.get_group_context(crypto_provider)?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.3.1
        let provisional_group_context = GroupContext {
            version: ProtocolVersion::MLS10,
            cipher_suite,
            group_id: old_group_context.group_id.clone(),
            epoch: new_group.epoch, /* this is updated */
            tree_hash: new_group
                .ratchet_tree
                .compute_root_tree_hash(crypto_provider, cipher_suite)?,
            confirmed_transcript_hash: old_group_context.confirmed_transcript_hash.clone(),
            extensions: new_group.extensions.clone().try_into()?,
        };

        let sender_node = new_group
            .ratchet_tree
            .get_leaf(sender_index)
            .expect("sender leaf exists and we found it previously")
            .clone();

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.5
        let update_path = UpdatePath::from_leaf_node(
            sender_node.clone(),
            parent_nodes,
            crypto_provider,
            cipher_suite,
            &provisional_group_context,
            &path_secret,
        )?;
        commit.path = Some(update_path);

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.4

        // If ExternalInit proposal, re-initialize the group
        if let Some(external_init_kem_key) = external_init_kem_output {
            todo!("https://www.rfc-editor.org/rfc/rfc9420.html#name-external-initialization");
        }

        if let Some(reinit_group_info) = reinit_proposal {
            todo!("https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.13.1");
        }

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.5
        let framed_content = FramedContent {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            sender: Sender::Member(sender_index),
            authenticated_data: Bytes::new(), //todo?
            content: Content::Commit(commit),
        };

        let framed_content_tbs = FramedContentTBS {
            version: ProtocolVersion::MLS10,
            wire_format: WireFormat::PrivateMessage,
            content: framed_content.clone(),
            context: Some(old_group_context.clone()),
        };

        let framed_content_signature = crypto_provider.sign_with_label(
            cipher_suite,
            self.signature_key_pair.private_key(),
            b"FramedContentTBS",
            &framed_content_tbs.serialize_detached()?,
        )?;

        let old_joiner_secret = old_group_context.extract_joiner_secret(
            crypto_provider,
            &self.init_secret,
            &commit_secret,
        )?;
        let old_epoch_secret =
            old_group_context.extract_epoch_secret(crypto_provider, &old_joiner_secret, &[])?;
        let old_confirmation_key =
            crypto_provider.derive_secret(cipher_suite, &old_epoch_secret, SECRET_LABEL_CONFIRM)?;
        let old_confirmation_tag = crypto_provider.sign_mac(
            cipher_suite,
            &old_confirmation_key,
            &old_group_context.confirmed_transcript_hash,
        )?;
        let confirmed_transcript_hash_input = new_group.hash_new_confirmed_transcript_hash(
            crypto_provider,
            &ConfirmedTranscriptHashInput {
                wire_format: WireFormat::PrivateMessage,
                content: framed_content.clone(),
                signature: framed_content_signature,
            },
            &InterimTranscriptHashInput {
                confirmation_tag: old_confirmation_tag,
            },
        )?;

        new_group.confirmed_transcript_hash = confirmed_transcript_hash_input.into();
        let new_group_context = new_group.get_group_context(crypto_provider)?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.5.2.5
        let new_init_secret = self.init_secret.clone();
        let new_joiner_secret = new_group_context.extract_joiner_secret(
            crypto_provider,
            &new_init_secret,
            &commit_secret,
        )?;
        let new_epoch_secret =
            new_group_context.extract_epoch_secret(crypto_provider, &new_joiner_secret, &[])?;
        let new_confirmation_key =
            crypto_provider.derive_secret(cipher_suite, &new_epoch_secret, SECRET_LABEL_CONFIRM)?;

        let new_confirmation_tag = crypto_provider.sign_mac(
            cipher_suite,
            &new_confirmation_key,
            &new_group_context.confirmed_transcript_hash,
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.8.2.4
        let new_interim_transcript_hash_input = InterimTranscriptHashInput {
            confirmation_tag: new_confirmation_tag.clone(),
        };

        let sender_data_secret = crypto_provider.derive_secret(
            cipher_suite,
            &new_epoch_secret,
            SECRET_LABEL_SENDER_DATA,
        )?;

        let encryption_secret = crypto_provider.derive_secret(
            cipher_suite,
            &new_epoch_secret,
            SECRET_LABEL_ENCRYPTION,
        )?;

        // todo put in ratchettree function?
        let secret_tree = SecretTree::new(
            crypto_provider,
            cipher_suite,
            new_group.ratchet_tree.num_leaves(),
            &encryption_secret,
        )?;

        new_group.our_generation += 1;
        let generation = new_group.our_generation;

        let content = SenderData::new(sender_index, generation)?;
        let ratchet_secret = secret_tree.derive_ratchet_root(
            crypto_provider,
            cipher_suite,
            sender_index.node_index(),
            RatchetLabel::Application,
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.9.1
        let private_message = PrivateMessage::new(
            crypto_provider,
            cipher_suite,
            self.signature_key_pair.public_key(),
            &ratchet_secret,
            &sender_data_secret,
            &framed_content,
            &content,
            &new_group_context,
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.10.1

        // Update extensions to get new Ratchet Tree in group info
        let new_extensions = new_group_context.extensions.clone();
        let group_info = GroupInfo::new(
            crypto_provider,
            new_group_context,
            new_extensions,
            new_confirmation_tag,
            sender_index,
            self.signature_key_pair.public_key(),
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.10.2.6
        let welcome_secret =
            extract_welcome_secret(crypto_provider, cipher_suite, &new_joiner_secret, &[])?;
        let (welcome_key, welcome_nonce) =
            Welcome::extract_key_and_nonce(welcome_secret, crypto_provider, cipher_suite)?;
        let group_info_serialized = group_info.serialize_detached()?;
        // AEAD seal serialized group info with welcome key+nonce
        let encrypted_group_info = crypto_provider.hpke(cipher_suite)?.aead_seal(
            &welcome_key,
            &welcome_nonce,
            &group_info_serialized,
            &[], /* no additional data */
        )?;

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.11.1
        let mut all_encrypted_secrets = Vec::new();
        if let Some(new_members) = new_members_key_packages {
            for new_member in new_members {
                // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.11.2.1
                let mut common_ancestor: Option<NodeIndex> = None;

                let mut nodes_of_path = HashSet::new();

                let (new_member_index, ok) = new_group
                    .ratchet_tree
                    .find_leaf(&new_member.payload.leaf_node);
                let (our_index, ok2) = new_group.ratchet_tree.find_leaf(&sender_node);
                debug_assert!(ok, "new member is in the tree");
                debug_assert!(ok2, "we are in the tree");

                let new_member_path = new_member_index.node_index();
                let our_path = our_index.node_index();

                nodes_of_path.insert(new_member_path);
                nodes_of_path.insert(our_path);

                let num_leaves = new_group.ratchet_tree.num_leaves();
                loop {
                    let (new_member_path, ok1) = num_leaves.parent(new_member_path);
                    let (our_path, ok2) = num_leaves.parent(our_path);
                    if !ok1 || !ok2 {
                        break;
                    }
                    if !nodes_of_path.insert(new_member_path) {
                        common_ancestor = Some(new_member_path);
                        break;
                    }
                    if !nodes_of_path.insert(our_path) {
                        common_ancestor = Some(our_path);
                        break;
                    }
                }

                let common_ancestor_node = match common_ancestor {
                    Some(node) => node,
                    None => return Err(Error::InvalidLeafNode),
                };

                // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.11.2.2
                /* todo: optional `path` value? */
                let member_path_secret = new_group.ratchet_tree.update_direct_path(
                    crypto_provider,
                    CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                    common_ancestor_node.leaf_index().0,
                    self.signature_key_pair.private_key(),
                    self.group_id.clone(),
                )?;

                let commit_secret =
                    crypto_provider.derive_secret(cipher_suite, &path_secret, b"path")?;

                // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.11.2.3
                let group_secrets = GroupSecrets {
                    joiner_secret: new_joiner_secret.clone(),
                    path_secret: Some(member_path_secret),
                    psk_ids: vec![],
                };

                let group_secrets_bytes = group_secrets.serialize_detached()?;

                let (kem_output, ciphertext) = crypto_provider.encrypt_with_label(
                    cipher_suite,
                    &new_member.payload.init_key,
                    b"Welcome",
                    &encrypted_group_info,
                    &group_secrets_bytes,
                )?;

                let encrypted_group_secrets = EncryptedGroupSecrets::new(
                    new_member.generate_ref(crypto_provider)?,
                    HPKECiphertext {
                        kem_output,
                        ciphertext,
                    },
                );

                all_encrypted_secrets.push(encrypted_group_secrets);
            }
        }

        // https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.1-3.12
        let welcome = Welcome {
            cipher_suite,
            secrets: all_encrypted_secrets,
            encrypted_group_info,
        };

        std::mem::swap(self, &mut new_group);

        Ok((private_message, welcome))
    }

    pub fn create_welcome(
        &mut self,
        key_package: KeyPackage,
        crypto_provider: &impl CryptoProvider,
    ) -> Result<(PrivateMessage, Welcome)> {
        Ok(self.create_commit(
            vec![Proposal::Add(AddProposal {
                key_package: key_package.clone(),
            })],
            crypto_provider,
            Some(vec![key_package]),
        )?)
    }
}
