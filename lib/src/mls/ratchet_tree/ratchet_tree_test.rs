use leaf_node::{TreeInfoTBS, TreePosition};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::UNIX_EPOCH;

use crate::mls::crypto::provider::RustCryptoProvider;
use crate::mls::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::mls::framing::*;
use crate::mls::key_schedule::GroupContext;
use crate::mls::ratchet_tree::*;
use crate::mls::utilities::error::*;
use crate::mls::utilities::serde::serde_test::load_test_vector;
use crate::mls::utilities::serde::Deserializer;
use crate::mls::utilities::tree_math::*;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeHash(#[serde(with = "hex")] Vec<u8>);

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeValidationTest {
    cipher_suite: u16,
    #[serde(with = "hex")]
    tree: Vec<u8>,
    #[serde(with = "hex")]
    group_id: Vec<u8>,

    resolutions: Vec<Vec<NodeIndex>>,
    tree_hashes: Vec<TreeHash>,
}

#[allow(clippy::cast_possible_truncation)]
fn tree_validation_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeValidationTest,
) -> Result<()> {
    let tree = RatchetTree::deserialize_exact(&tc.tree)?;

    for (i, want) in tc.resolutions.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let res = tree.resolve(x);
        assert_eq!(&res, want);
    }

    let exclude = HashSet::new();
    for (i, want) in tc.tree_hashes.iter().enumerate() {
        let x = NodeIndex(i as u32);
        let h = tree.compute_tree_hash(crypto_provider, cipher_suite, x, &exclude)?;
        assert_eq!(&h, &want.0);
    }

    assert!(
        tree.verify_parent_hashes(crypto_provider, cipher_suite),
        "verifyParentHashes() failed"
    );

    let group_id: MlsGroupId = tc.group_id.clone().into();
    for (i, node) in tree.0.iter().enumerate() {
        if let Some(Node::Leaf(leaf_node)) = node {
            let (leaf_index, ok) = NodeIndex(i as u32).leaf_index();
            assert!(ok, "leafIndex({i:?}) = false");

            let tree_info_tbs = TreeInfoTBS::UpdateOrCommit(TreePosition {
                group_id: group_id.clone(),
                leaf_index,
            });
            assert!(
                leaf_node.verify_signature(crypto_provider, cipher_suite, tree_info_tbs),
                "verify({leaf_index:?}) = false"
            );
        }
    }

    Ok(())
}

fn test_tree_validation_with_crypto_provider(
    tests: &[TreeValidationTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_tree_validation {}:{}", cipher_suite, tc.cipher_suite);

        if crypto_provider.supports(cipher_suite) {
            tree_validation_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_tree_validation() -> Result<()> {
    let tests: Vec<TreeValidationTest> = load_test_vector("test-vectors/tree-validation.json")?;

    test_tree_validation_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct PathSecretTest {
    node: u32,
    #[serde(with = "hex")]
    path_secret: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct LeafPrivateTest {
    index: u32,
    #[serde(with = "hex")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex")]
    signature_priv: Vec<u8>,
    path_secrets: Vec<PathSecretTest>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct PathTest {
    sender: u32,
    #[serde(with = "hex")]
    update_path: Vec<u8>,
    path_secrets: Vec<Option<String>>,
    #[serde(with = "hex")]
    commit_secret: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_after: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeKEMTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex")]
    ratchet_tree: Vec<u8>,

    pub leaves_private: Vec<LeafPrivateTest>,
    pub update_paths: Vec<PathTest>,
}

fn tree_kem_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeKEMTest,
) -> Result<()> {
    // TODO: test leaves_private

    for update_path_test in &tc.update_paths {
        let mut tree = RatchetTree::deserialize_exact(&tc.ratchet_tree)?;

        let up = UpdatePath::deserialize_exact(&update_path_test.update_path)?;

        // TODO: verify that UpdatePath is parent-hash valid relative to ratchet tree
        // TODO: process UpdatePath using private leaves

        tree.merge_update_path(
            crypto_provider,
            cipher_suite,
            LeafIndex(update_path_test.sender),
            &up,
        )?;

        let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
        assert_eq!(&tree_hash, &update_path_test.tree_hash_after);

        // TODO: create and verify new update path
    }

    Ok(())
}

fn test_tree_kem_with_crypto_provider(
    tests: &[TreeKEMTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for (i, tc) in tests.iter().enumerate() {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_tree_kem {i}:{cipher_suite}");

        if crypto_provider.supports(cipher_suite) {
            tree_kem_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_tree_kem() -> Result<()> {
    let tests: Vec<TreeKEMTest> = load_test_vector("test-vectors/treekem.json")?;

    test_tree_kem_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct TreeOperationsTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    tree_before: Vec<u8>,
    #[serde(with = "hex")]
    proposal: Vec<u8>,
    proposal_sender: u32,
    #[serde(with = "hex")]
    tree_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_after: Vec<u8>,
    #[serde(with = "hex")]
    tree_hash_before: Vec<u8>,
}

fn tree_operations_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &TreeOperationsTest,
) -> Result<()> {
    let mut tree = RatchetTree::deserialize_exact(&tc.tree_before)?;

    let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
    assert_eq!(&tree_hash, &tc.tree_hash_before);

    let prop = Proposal::deserialize_exact(&tc.proposal)?;

    match &prop {
        Proposal::Add(add) => {
            let ctx = GroupContext {
                version: add.key_package.payload.version,
                cipher_suite: add.key_package.payload.cipher_suite,
                ..Default::default()
            };
            add.key_package.verify(crypto_provider, &ctx)?;
            tree.add(add.key_package.payload.leaf_node.clone());
        }
        Proposal::Update(update) => {
            let (signature_keys, encryption_keys) = tree.keys();
            update.leaf_node.verify(
                crypto_provider,
                LeafNodeVerifyOptions {
                    cipher_suite,
                    group_id: &Bytes::new(),
                    leaf_index: LeafIndex(tc.proposal_sender),
                    supported_creds: &tree.supported_creds(),
                    signature_keys: &signature_keys,
                    encryption_keys: &encryption_keys,
                    now: &|| -> SystemTime { UNIX_EPOCH },
                },
            )?;
            tree.update(LeafIndex(tc.proposal_sender), update.leaf_node.clone());
        }
        Proposal::Remove(remove) => {
            assert!(
                tree.get_leaf(remove.removed).is_some(),
                "leaf node {:?} is blank",
                remove.removed
            );
            tree.remove(remove.removed);
        }
        _ => unreachable!(),
    }

    let raw_tree = tree.serialize_detached()?;
    assert_eq!(&raw_tree, &tc.tree_after);

    let tree_hash = tree.compute_root_tree_hash(crypto_provider, cipher_suite)?;
    assert_eq!(&tree_hash, &tc.tree_hash_after);

    Ok(())
}

fn test_tree_operations_with_crypto_provider(
    tests: &[TreeOperationsTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for (i, tc) in tests.iter().enumerate() {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_tree_operations {i}:{cipher_suite}");

        tree_operations_test(crypto_provider, cipher_suite, tc)?;
    }

    Ok(())
}

#[test]
fn test_tree_operations() -> Result<()> {
    let tests: Vec<TreeOperationsTest> = load_test_vector("test-vectors/tree-operations.json")?;

    test_tree_operations_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}
