use serde::{Deserialize, Serialize};

use crate::mls::crypto::provider::RustCryptoProvider;
use crate::mls::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::mls::extensibility::Extensions;
use crate::mls::framing::{private_message::*, public_message::*, *};
use crate::mls::key_schedule::GroupContext;
use crate::mls::secret_tree::*;
use crate::mls::utilities::error::*;
use crate::mls::utilities::serde::{serde_test::load_test_vector, *};

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct WelcomeTest {
    cipher_suite: u16,
    #[serde(with = "hex")]
    init_priv: Vec<u8>,
    #[serde(with = "hex")]
    signer_pub: Vec<u8>,
    #[serde(with = "hex")]
    key_package: Vec<u8>,
    #[serde(with = "hex")]
    welcome: Vec<u8>,
}

fn welcome_test(
    crypto_provider: &impl CryptoProvider,
    _cipher_suite: CipherSuite,
    tc: &WelcomeTest,
) -> Result<()> {
    let welcome_msg = MlsEncodedMessage::deserialize_exact(&tc.welcome)?;
    assert_eq!(welcome_msg.wire_message.wire_format(), WireFormat::Welcome);

    let WireMessage::Welcome(welcome) = welcome_msg.wire_message else {
        unreachable!();
    };

    let key_package_msg = MlsEncodedMessage::deserialize_exact(&tc.key_package)?;
    assert_eq!(
        key_package_msg.wire_message.wire_format(),
        WireFormat::KeyPackage
    );

    let WireMessage::KeyPackage(key_package) = key_package_msg.wire_message else {
        unreachable!();
    };

    let key_package_ref = key_package.generate_ref(crypto_provider)?;

    let group_secrets =
        welcome.decrypt_group_secrets(crypto_provider, &key_package_ref, &tc.init_priv)?;

    let group_info =
        welcome.decrypt_group_info(crypto_provider, &group_secrets.joiner_secret, &[])?;

    assert!(group_info
        .verify_signature(crypto_provider, &tc.signer_pub)
        .is_ok());

    assert!(group_info
        .verify_confirmation_tag(crypto_provider, &group_secrets.joiner_secret, &[])
        .is_ok());

    Ok(())
}

fn test_welcome_with_crypto_provider(
    tests: &[WelcomeTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!("test_welcome {}:{}", cipher_suite, tc.cipher_suite);

        if crypto_provider.supports(cipher_suite) {
            welcome_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_welcome() -> Result<()> {
    let tests: Vec<WelcomeTest> = load_test_vector("test-vectors/welcome.json")?;

    test_welcome_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
struct MessageProtectionTest {
    cipher_suite: u16,

    #[serde(with = "hex")]
    group_id: Vec<u8>,
    epoch: u64,
    #[serde(with = "hex")]
    tree_hash: Vec<u8>,
    #[serde(with = "hex")]
    confirmed_transcript_hash: Vec<u8>,

    #[serde(with = "hex")]
    signature_priv: Vec<u8>,
    #[serde(with = "hex")]
    signature_pub: Vec<u8>,

    #[serde(with = "hex")]
    encryption_secret: Vec<u8>,
    #[serde(with = "hex")]
    sender_data_secret: Vec<u8>,
    #[serde(with = "hex")]
    membership_key: Vec<u8>,

    #[serde(with = "hex")]
    proposal: Vec<u8>,
    #[serde(with = "hex")]
    proposal_pub: Vec<u8>,
    #[serde(with = "hex")]
    proposal_priv: Vec<u8>,

    #[serde(with = "hex")]
    commit: Vec<u8>,
    #[serde(with = "hex")]
    commit_pub: Vec<u8>,
    #[serde(with = "hex")]
    commit_priv: Vec<u8>,

    #[serde(with = "hex")]
    application: Vec<u8>,
    #[serde(with = "hex")]
    application_priv: Vec<u8>,
}

fn test_message_protection_pub(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    want_raw: &[u8],
    raw_pub: &[u8],
) -> Result<()> {
    let msg = MlsEncodedMessage::deserialize_exact(raw_pub)?;
    assert_eq!(msg.wire_message.wire_format(), WireFormat::PublicMessage);
    let WireMessage::PublicMessage(pub_msg) = msg.wire_message else {
        unreachable!();
    };

    verify_public_message(crypto_provider, cipher_suite, tc, ctx, &pub_msg, want_raw)?;

    let mut pub_msg = PublicMessage::new(
        crypto_provider,
        cipher_suite,
        &tc.signature_priv,
        &pub_msg.content,
        ctx,
    )?;

    pub_msg.sign_membership_tag(crypto_provider, cipher_suite, &tc.membership_key, ctx)?;

    verify_public_message(crypto_provider, cipher_suite, tc, ctx, &pub_msg, want_raw)
}

fn verify_public_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    pub_msg: &PublicMessage,
    want_raw: &[u8],
) -> Result<()> {
    let auth_content = pub_msg.authenticated_content();
    assert!(auth_content
        .verify_signature(crypto_provider, cipher_suite, &tc.signature_pub, ctx)
        .is_ok());
    assert!(pub_msg
        .verify_membership_tag(crypto_provider, cipher_suite, &tc.membership_key, ctx)
        .is_ok());

    let raw = match &pub_msg.content.content {
        Content::Application(application) => application.clone(),
        Content::Proposal(proposal) => proposal.serialize_detached()?,
        Content::Commit(commit) => commit.serialize_detached()?,
    };
    assert_eq!(raw.as_ref(), want_raw);

    Ok(())
}

fn decrypt_private_message(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
    ctx: &GroupContext,
    mut secret: RatchetSecret,
    priv_msg: &PrivateMessage,
    want_raw: &[u8],
) -> Result<PrivateMessageContent> {
    let sender_data = priv_msg.decrypt_sender_data(crypto_provider, ctx, &tc.sender_data_secret)?;

    while secret.generation != sender_data.generation {
        secret = secret.derive_next(crypto_provider, cipher_suite)?;
    }

    let content =
        priv_msg.decrypt_content(crypto_provider, ctx, &secret, &sender_data.reuse_guard)?;

    let auth_content = priv_msg.authenticated_content(ctx, &sender_data, &content);
    assert!(auth_content
        .verify_signature(crypto_provider, cipher_suite, &tc.signature_pub, ctx)
        .is_ok());

    let raw = match &content.content {
        Content::Application(application) => application.clone(),
        Content::Proposal(proposal) => proposal.serialize_detached()?,
        Content::Commit(commit) => commit.serialize_detached()?,
    };
    assert_eq!(raw.as_ref(), want_raw);

    Ok(content)
}

fn message_protection_test(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    tc: &MessageProtectionTest,
) -> Result<()> {
    let ctx = GroupContext {
        version: ProtocolVersion::MLS10,
        cipher_suite,
        group_id: tc.group_id.clone().into(),
        epoch: tc.epoch,
        tree_hash: tc.tree_hash.clone().into(),
        confirmed_transcript_hash: tc.confirmed_transcript_hash.clone().into(),
        extensions: Extensions::default(),
    };

    let wire_formats = vec![
        (
            "proposal",
            tc.proposal.clone(),
            tc.proposal_pub.clone(),
            tc.proposal_priv.clone(),
        ),
        (
            "commit",
            tc.commit.clone(),
            tc.commit_pub.clone(),
            tc.commit_priv.clone(),
        ),
        (
            "application",
            tc.application.clone(),
            vec![],
            tc.application_priv.clone(),
        ),
    ];
    for wf in wire_formats {
        println!("testing {}", wf.0);
        if !wf.2.is_empty() {
            test_message_protection_pub(crypto_provider, cipher_suite, tc, &ctx, &wf.1, &wf.2)?;
        }
    }

    Ok(())
}

fn test_message_protection_with_crypto_provider(
    tests: &[MessageProtectionTest],
    crypto_provider: &impl CryptoProvider,
) -> Result<()> {
    for tc in tests {
        let cipher_suite: CipherSuite = tc.cipher_suite.into();
        println!(
            "test_message_protection {}:{}",
            cipher_suite, tc.cipher_suite
        );

        if crypto_provider.supports(cipher_suite) {
            message_protection_test(crypto_provider, cipher_suite, tc)?;
        }
    }

    Ok(())
}

#[test]
fn test_message_protection() -> Result<()> {
    let tests: Vec<MessageProtectionTest> =
        load_test_vector("test-vectors/message-protection.json")?;

    test_message_protection_with_crypto_provider(&tests, &RustCryptoProvider::default())?;

    Ok(())
}
