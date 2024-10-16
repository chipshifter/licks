use bytes::Bytes;
use serde::{self, de::DeserializeOwned, Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use std::{fs::File, io::BufReader, path::Path};

use crate::mls::crypto::provider::RustCryptoProvider;
use crate::mls::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::mls::extensibility::*;
use crate::mls::framing::proposal::*;
use crate::mls::framing::*;
use crate::mls::key_schedule::*;
use crate::mls::ratchet_tree::{leaf_node::*, *};
use crate::mls::utilities::error::*;
use crate::mls::utilities::serde::Deserializer;

pub(crate) fn load_test_vector<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> Result<T> {
    let file = File::open(path).map_err(|err| Error::Other(err.to_string()))?;
    let reader = BufReader::new(file);
    Ok(serde_json::from_reader(reader)?)
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct ExternalPskTest {
    #[serde(with = "hex")]
    psk_id: Vec<u8>,
    #[serde(with = "hex")]
    psk: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct VecTest(#[serde(with = "hex")] Vec<u8>);

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct EpochTest {
    proposals: Vec<VecTest>,
    #[serde(with = "hex")]
    commit: Vec<u8>,
    #[serde(with = "hex")]
    epoch_authenticator: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
struct PassiveClientTest {
    cipher_suite: u16,
    external_psks: Vec<ExternalPskTest>,

    #[serde(with = "hex")]
    key_package: Vec<u8>,
    #[serde(with = "hex")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex")]
    encryption_priv: Vec<u8>,
    #[serde(with = "hex")]
    init_priv: Vec<u8>,
    #[serde(with = "hex")]
    welcome: Vec<u8>,
    ratchet_tree: Option<VecTest>,
    #[serde(with = "hex")]
    initial_epoch_authenticator: Vec<u8>,
    epochs: Vec<EpochTest>,
}

#[allow(clippy::too_many_lines)]
fn passive_client_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &PassiveClientTest,
) -> Result<()> {
    let msg = deserialize_message(&tc.welcome, WireFormat::Welcome)?;
    let WireMessage::Welcome(welcome) = msg.wire_message else {
        unreachable!();
    };

    let msg = deserialize_message(&tc.key_package, WireFormat::KeyPackage)?;
    let WireMessage::KeyPackage(key_pkg) = msg.wire_message else {
        unreachable!();
    };

    check_encryption_key_pair(
        crypto_provider,
        cipher_suite,
        &key_pkg.payload.init_key,
        &tc.init_priv,
    )?;
    check_encryption_key_pair(
        crypto_provider,
        cipher_suite,
        &key_pkg.payload.leaf_node.payload.encryption_key,
        &tc.encryption_priv,
    )?;
    check_signature_key_pair(
        crypto_provider,
        cipher_suite,
        &key_pkg.payload.leaf_node.payload.signature_key,
        &tc.signature_priv,
    )?;

    let key_pkg_ref = key_pkg.generate_ref(crypto_provider)?;

    let group_secrets =
        welcome.decrypt_group_secrets(crypto_provider, &key_pkg_ref, &tc.init_priv)?;

    assert!(group_secrets.verify_single_reinit_or_branch_psk());

    let mut psks: Vec<Bytes> = vec![];
    for psk_id in &group_secrets.psk_ids {
        if let PSK::External(epsk_id) = &psk_id.psk {
            let mut found = false;
            for epsk in &tc.external_psks {
                if epsk.psk_id == epsk_id.as_ref() {
                    psks.push(epsk.psk.clone().into());
                    found = true;
                    break;
                }
            }
            assert!(found);
        } else {
            unreachable!();
        }
    }

    let psk_secret =
        extract_psk_secret(crypto_provider, cipher_suite, &group_secrets.psk_ids, &psks)?;

    let group_info =
        welcome.decrypt_group_info(crypto_provider, &group_secrets.joiner_secret, &psk_secret)?;

    let raw_tree = if let Some(raw_tree) = &tc.ratchet_tree {
        raw_tree.0.clone().into()
    } else {
        group_info
            .extensions
            .find_extension_data(ExtensionType::RatchetTree)
            .ok_or(Error::Other("missing ratchet tree".to_string()))?
    };

    let mut tree = RatchetTree::deserialize_exact(&raw_tree)?;

    let signer_node = tree
        .get_leaf(group_info.signer)
        .ok_or(Error::Other("signer node is blank".to_string()))?;
    assert!(group_info
        .verify_signature(crypto_provider, &signer_node.payload.signature_key)
        .is_ok());
    assert!(group_info
        .verify_confirmation_tag(crypto_provider, &group_secrets.joiner_secret, &psk_secret)
        .is_ok());
    assert_eq!(
        group_info.group_context.cipher_suite,
        key_pkg.payload.cipher_suite
    );

    let disable_lifetime_check = || -> SystemTime { UNIX_EPOCH };
    tree.verify_integrity(
        crypto_provider,
        &group_info.group_context,
        disable_lifetime_check,
    )?;

    let (_, ok) = tree.find_leaf(&key_pkg.payload.leaf_node);
    assert!(ok);

    // TODO: perform other group info verification steps

    let epoch_secret = group_info.group_context.extract_epoch_secret(
        crypto_provider,
        &group_secrets.joiner_secret,
        &psk_secret,
    )?;
    let epoch_authenticator =
        crypto_provider.derive_secret(cipher_suite, &epoch_secret, SECRET_LABEL_AUTHENTICATION)?;
    assert_eq!(
        epoch_authenticator.as_ref(),
        &tc.initial_epoch_authenticator
    );

    if let Some(epoch) = tc.epochs.first() {
        let msg = deserialize_message(&epoch.commit, WireFormat::PublicMessage)?;
        let WireMessage::PublicMessage(pub_msg) = msg.wire_message else {
            unreachable!();
        };

        assert_eq!(pub_msg.content.epoch, group_info.group_context.epoch);

        let Sender::Member(sender_leaf_index) = pub_msg.content.sender else {
            return Err(Error::Other("wrong sender type".to_string()));
        };

        // TODO: check tree length
        let sender_node = tree
            .get_leaf(sender_leaf_index)
            .ok_or(Error::Other("blank leaf node for sender".to_string()))?;

        let auth_content = pub_msg.authenticated_content();
        assert!(auth_content
            .verify_signature(
                crypto_provider,
                cipher_suite,
                &sender_node.payload.signature_key,
                &group_info.group_context
            )
            .is_ok());

        let membership_key =
            crypto_provider.derive_secret(cipher_suite, &epoch_secret, SECRET_LABEL_MEMBERSHIP)?;
        assert!(pub_msg
            .verify_membership_tag(
                crypto_provider,
                cipher_suite,
                &membership_key,
                &group_info.group_context
            )
            .is_ok());

        assert_eq!(
            auth_content.content.content.content_type(),
            ContentType::Commit
        );

        let Content::Commit(commit) = auth_content.content.content else {
            return Err(Error::Other("wrong content type".to_string()));
        };

        let mut proposals = vec![];
        let mut senders = vec![];
        for prop_or_ref in commit.proposals {
            match prop_or_ref {
                ProposalOrRef::Proposal(proposal) => {
                    proposals.push(proposal);
                    senders.push(sender_leaf_index);
                }
                ProposalOrRef::Reference(_) => {
                    //TODO: proposalOrRefTypeReference
                    return Err(Error::Other(
                        "//TODO: proposalOrRefTypeReference".to_string(),
                    ));
                }
            }
        }

        assert!(verify_proposal_list(&proposals, &senders, sender_leaf_index).is_ok());

        // TODO: additional proposal list checks

        for prop in &proposals {
            if let Proposal::PreSharedKey(_) = prop {
                panic!("no PSK available");
            }
        }

        let mut new_tree = tree.clone();
        new_tree.apply(&proposals, &senders);

        assert!(
            !(proposal_list_needs_path(&proposals) && commit.path.is_none()),
            "proposal list needs update path"
        );

        if let Some(path) = &commit.path {
            match path.leaf_node.payload.leaf_node_source {
                LeafNodeSource::Commit(_) => {}
                _ => panic!("commit path leaf node source must be commit"),
            }

            // The same signature key can be re-used, but the encryption key
            // must change
            let (mut signature_keys, encryption_keys) = tree.keys();
            signature_keys.remove(&sender_node.payload.signature_key);
            assert!(path
                .leaf_node
                .verify(
                    crypto_provider,
                    LeafNodeVerifyOptions {
                        cipher_suite,
                        group_id: &group_info.group_context.group_id,
                        leaf_index: sender_leaf_index,
                        supported_creds: &tree.supported_creds(),
                        signature_keys: &signature_keys,
                        encryption_keys: &encryption_keys,
                        now: &|| -> SystemTime { UNIX_EPOCH },
                    }
                )
                .is_ok());

            for update_node in &path.nodes {
                assert!(
                    !encryption_keys.contains(&update_node.encryption_key),
                    "encryption key in update path already used in ratchet tree"
                );
            }

            tree.merge_update_path(crypto_provider, cipher_suite, sender_leaf_index, path)?;
        }

        // TODO: apply commit
    }

    Ok(())
}

fn deserialize_message(raw: &[u8], wf: WireFormat) -> Result<MlsEncodedMessage> {
    let msg = MlsEncodedMessage::deserialize_exact(raw)?;
    assert_eq!(msg.wire_message.wire_format(), wf);
    Ok(msg)
}

fn check_encryption_key_pair(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    public_key: &[u8],
    private_key: &[u8],
) -> Result<()> {
    let want_plaintext = b"foo";
    let label = b"bar";

    let (kem_output, ciphertext) =
        crypto_provider.encrypt_with_label(cipher_suite, public_key, label, &[], want_plaintext)?;

    let plaintext = crypto_provider.decrypt_with_label(
        cipher_suite,
        private_key,
        label,
        &[],
        &kem_output,
        &ciphertext,
    )?;

    assert_eq!(plaintext.as_ref(), want_plaintext.as_ref());

    Ok(())
}

fn check_signature_key_pair(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    public_key: &[u8],
    private_key: &[u8],
) -> Result<()> {
    let content = b"foo";
    let label = b"bar";

    let signature = crypto_provider.sign_with_label(cipher_suite, private_key, label, content)?;

    assert!(crypto_provider
        .verify_with_label(cipher_suite, public_key, label, content, &signature)
        .is_ok());

    Ok(())
}

const TEST_VECTORS_PATHS: &[&str] = &[
    "test-vectors/passive-client-welcome.json",
    "test-vectors/passive-client-handling-commit.json",
    //TODO: "test-vectors/passive-client-random.json",
    // failed in ratchetTree.mergeUpdatePath() = mls: parent hash mismatch for update path's leaf node
];

fn test_passive_client_with_crypto_provider(
    tests: &[PassiveClientTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_passive_client {}:{}", cipher_suite, tc.cipher_suite);

        if crypto_provider.supports(cipher_suite) {
            passive_client_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_passive_client() -> Result<()> {
    for path in TEST_VECTORS_PATHS {
        println!("test_passive_client path = {path}");
        let tests: Vec<PassiveClientTest> = load_test_vector(path)?;

        test_passive_client_with_crypto_provider(&tests, &RustCryptoProvider::default())?;
    }

    Ok(())
}
