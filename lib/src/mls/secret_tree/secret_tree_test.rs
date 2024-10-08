use serde::{Deserialize, Serialize};

use crate::mls::crypto::provider::RustCryptoProvider;
use crate::mls::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::mls::framing::{expand_sender_data_key, expand_sender_data_nonce};
use crate::mls::secret_tree::*;
use crate::mls::utilities::error::*;
use crate::mls::utilities::serde::serde_test::load_test_vector;
use crate::mls::utilities::tree_math::LeafIndex;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SenderData {
    #[serde(with = "hex")]
    // `secret_data_secret` is the name of the JSON field
    // we're reading from
    #[allow(clippy::struct_field_names)]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex")]
    ciphertext: Vec<u8>,
    #[serde(with = "hex")]
    key: Vec<u8>,
    #[serde(with = "hex")]
    nonce: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct Leaf {
    generation: u32,
    #[serde(with = "hex")]
    handshake_key: Vec<u8>,
    #[serde(with = "hex")]
    handshake_nonce: Vec<u8>,
    #[serde(with = "hex")]
    application_key: Vec<u8>,
    #[serde(with = "hex")]
    application_nonce: Vec<u8>,
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct SecretTreeTest {
    cipher_suite: u16,
    sender_data: SenderData,
    #[serde(with = "hex")]
    encryption_secret: Vec<u8>,
    leaves: Vec<Vec<Leaf>>,
}

#[allow(clippy::cast_possible_truncation)]
fn secret_tree_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &SecretTreeTest,
) -> Result<()> {
    let key = expand_sender_data_key(
        crypto_provider,
        cipher_suite,
        &tc.sender_data.sender_data_secret,
        &tc.sender_data.ciphertext,
    )?;
    assert_eq!(&key, &tc.sender_data.key);

    let nonce = expand_sender_data_nonce(
        crypto_provider,
        cipher_suite,
        &tc.sender_data.sender_data_secret,
        &tc.sender_data.ciphertext,
    )?;
    assert_eq!(&nonce, &tc.sender_data.nonce);

    let tree = SecretTree::new(
        crypto_provider,
        cipher_suite,
        NumLeaves(tc.leaves.len() as u32),
        &tc.encryption_secret,
    )?;

    for (i, gens) in tc.leaves.iter().enumerate() {
        let li = LeafIndex(i as u32);
        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Handshake,
            gens,
        )?;

        test_ratchet_secret(
            crypto_provider,
            cipher_suite,
            &tree,
            li,
            RatchetLabel::Application,
            gens,
        )?;
    }

    Ok(())
}

fn test_ratchet_secret(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tree: &SecretTree,
    li: LeafIndex,
    label: RatchetLabel,
    gens: &[Leaf],
) -> Result<()> {
    let mut secret =
        tree.derive_ratchet_root(crypto_provider, cipher_suite, li.node_index(), label)?;

    for gen in gens {
        assert!(gen.generation >= secret.generation);

        while secret.generation != gen.generation {
            secret = secret.derive_next(crypto_provider, cipher_suite)?;
        }

        let (want_key, want_nonce) = match label {
            RatchetLabel::Handshake => (&gen.handshake_key, &gen.handshake_nonce),
            RatchetLabel::Application => (&gen.application_key, &gen.application_nonce),
        };

        let key = secret.derive_key(crypto_provider, cipher_suite)?;
        assert_eq!(&key, &want_key);

        let nonce = secret.derive_nonce(crypto_provider, cipher_suite)?;
        assert_eq!(&nonce, &want_nonce);
    }

    Ok(())
}

fn test_secret_tree_with_crypto_provider(
    tests: &[SecretTreeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_secret_tree {cipher_suite}");
        if crypto_provider.supports(cipher_suite) {
            secret_tree_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_secret_tree() -> Result<()> {
    let tests: Vec<SecretTreeTest> = load_test_vector("test-vectors/secret-tree.json")?;

    test_secret_tree_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}
