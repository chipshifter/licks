//! [RFC9420 Sec.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-10) Key Packages
//!
//! In order to facilitate the asynchronous addition of clients to a group, clients can pre-publish
//! `KeyPackage` objects that provide some public information about a user. A `KeyPackage` object specifies:
//!
//! 1. a protocol version and cipher suite that the client supports,
//! 2. a public key that others can use to encrypt a Welcome message to this client (an "init key"), and
//! 3. the content of the leaf node that should be added to the tree to represent this client.

pub mod builder;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::ops::Deref;

use crate::crypto::rng::random_bytes_vec;
use crate::mls::crypto::key_pair::EncryptionKeyPair;
use crate::mls::crypto::{
    cipher_suite::CipherSuite, config::CryptoConfig, credential::Credential,
    key_pair::SignatureKeyPair, provider::CryptoProvider, HPKEPrivateKey, HPKEPublicKey,
};
use crate::mls::extensibility::Extensions;
use crate::mls::framing::ProtocolVersion;
use crate::mls::key_package::builder::KeyPackageBuilder;
use crate::mls::key_schedule::GroupContext;
use crate::mls::ratchet_tree::leaf_node::{
    Capabilities, LeafNode, LeafNodeSource, Lifetime, TreeInfoTBS,
};
use crate::mls::utilities::{
    error::{Error, Result},
    serde::{deserialize_opaque_vec, serialize_opaque_vec, Deserializer, Serializer},
};

const KEY_PACKAGE_SIGNATURE_LABEL: &str = "KeyPackageTBS";

/// [RFC9420 Sec.5.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2) `KeyPackageRef`
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct KeyPackageRef(Bytes);

impl Deref for KeyPackageRef {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for KeyPackageRef {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(KeyPackageRef(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for KeyPackageRef {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}

/// [RFC9420 Sec.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-10) `KeyPackageTBS`
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct KeyPackageTBS {
    pub(crate) version: ProtocolVersion,
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) init_key: HPKEPublicKey,
    pub(crate) leaf_node: LeafNode,
    pub(crate) extensions: Extensions,
}

impl Deserializer for KeyPackageTBS {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 4 {
            return Err(Error::BufferTooSmall);
        }

        let version = buf.get_u16().into();
        let cipher_suite = buf.get_u16().into();
        let init_key = HPKEPublicKey::deserialize(buf)?;
        let leaf_node = LeafNode::deserialize(buf)?;
        let extensions = Extensions::deserialize(buf)?;

        Ok(Self {
            version,
            cipher_suite,
            init_key,
            leaf_node,
            extensions,
        })
    }
}

impl Serializer for KeyPackageTBS {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.version.into());
        buf.put_u16(self.cipher_suite.into());
        serialize_opaque_vec(&self.init_key, buf)?;
        self.leaf_node.serialize(buf)?;
        self.extensions.serialize(buf)
    }
}

/// [RFC9420 Sec.10](https://www.rfc-editor.org/rfc/rfc9420.html#section-10) `KeyPackage`
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct KeyPackage {
    pub(crate) payload: KeyPackageTBS,
    signature: Bytes,
}

impl Deserializer for KeyPackage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let payload = KeyPackageTBS::deserialize(buf)?;
        let signature = deserialize_opaque_vec(buf)?;

        Ok(Self { payload, signature })
    }
}

impl Serializer for KeyPackage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.payload.serialize(buf)?;
        serialize_opaque_vec(&self.signature, buf)
    }
}

impl KeyPackage {
    /// Create a key package builder
    pub fn builder() -> KeyPackageBuilder {
        KeyPackageBuilder::new()
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        crypto_provider: &impl CryptoProvider,
        crypto_config: CryptoConfig,
        credential: Credential,
        signature_key_pair: &SignatureKeyPair,
        key_package_lifetime: Lifetime,
        key_package_extensions: Extensions,
        leaf_node_capabilities: Capabilities,
        leaf_node_extensions: Extensions,
    ) -> Result<(Self, EncryptionKeyPair, HPKEPrivateKey)> {
        if crypto_provider
            .signature(crypto_config.cipher_suite)?
            .signature_scheme()
            != signature_key_pair.signature_scheme()
        {
            return Err(Error::CipherSuiteNotMatchSignatureScheme);
        }

        // Create a new HPKE key pair
        let ikm = random_bytes_vec(crypto_provider.hash(crypto_config.cipher_suite)?.size());

        let init_key = crypto_provider
            .hpke(crypto_config.cipher_suite)?
            .kem_derive_key_pair(&ikm)?;

        let (key_package, encryption_key_pair) = Self::from_keys(
            crypto_provider,
            crypto_config,
            credential,
            signature_key_pair,
            key_package_lifetime,
            key_package_extensions,
            leaf_node_capabilities,
            leaf_node_extensions,
            init_key.public_key,
        )?;

        Ok((key_package, encryption_key_pair, init_key.private_key))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_keys(
        crypto_provider: &impl CryptoProvider,
        crypto_config: CryptoConfig,
        credential: Credential,
        signature_key_pair: &SignatureKeyPair,
        key_package_lifetime: Lifetime,
        key_package_extensions: Extensions,
        leaf_node_capabilities: Capabilities,
        leaf_node_extensions: Extensions,
        init_key: HPKEPublicKey,
    ) -> Result<(Self, EncryptionKeyPair)> {
        let (leaf_node, encryption_key_pair) = LeafNode::new(
            crypto_provider,
            crypto_config.cipher_suite,
            credential,
            signature_key_pair,
            LeafNodeSource::KeyPackage(key_package_lifetime),
            leaf_node_capabilities,
            leaf_node_extensions,
            TreeInfoTBS::KeyPackage,
        )?;

        let payload = KeyPackageTBS {
            version: crypto_config.version,
            cipher_suite: crypto_config.cipher_suite,
            init_key,
            leaf_node,
            extensions: key_package_extensions,
        };

        let signature = crypto_provider.sign_with_label(
            crypto_config.cipher_suite,
            &signature_key_pair.public_key,
            KEY_PACKAGE_SIGNATURE_LABEL.as_bytes(),
            &payload.serialize_detached()?,
        )?;

        Ok((Self { payload, signature }, encryption_key_pair))
    }

    fn verify_signature(&self, crypto_provider: &impl CryptoProvider) -> Result<()> {
        let mut buf = BytesMut::new();
        self.payload.serialize(&mut buf)?;
        let raw = buf.freeze();
        crypto_provider.verify_with_label(
            self.payload.cipher_suite,
            &self.payload.leaf_node.payload.signature_key,
            KEY_PACKAGE_SIGNATURE_LABEL.as_bytes(),
            &raw,
            &self.signature,
        )
    }

    /// [RFC9420 Sec.10.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-10.1) `KeyPackage` Validation
    pub fn verify(&self, crypto_provider: &impl CryptoProvider, ctx: &GroupContext) -> Result<()> {
        if self.payload.version != ctx.version {
            return Err(Error::KeyPackageVersionNotMatchGroupContext);
        }
        if self.payload.cipher_suite != ctx.cipher_suite {
            return Err(Error::CipherSuiteNotMatchGroupContext);
        }
        if let LeafNodeSource::KeyPackage(_) = &self.payload.leaf_node.payload.leaf_node_source {
        } else {
            return Err(Error::KeyPackageContainsLeafNodeWithInvalidSource);
        }
        if self.verify_signature(crypto_provider).is_err() {
            return Err(Error::InvalidKeyPackageSignature);
        }
        if self.payload.leaf_node.payload.encryption_key == self.payload.init_key {
            return Err(Error::KeyPackageEncryptionKeyAndInitKeyIdentical);
        }
        Ok(())
    }

    /// [RFC9420 Sec.5.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2) Generate a `KeyPackageRef`
    /// with the value input is the encoded `KeyPackage`, and the cipher suite specified in
    /// the `KeyPackage` determines the KDF used
    pub fn generate_ref(&self, crypto_provider: &impl CryptoProvider) -> Result<KeyPackageRef> {
        let mut buf = BytesMut::new();
        self.serialize(&mut buf)?;
        let raw = buf.freeze();

        Ok(KeyPackageRef(crypto_provider.ref_hash(
            self.payload.cipher_suite,
            b"MLS 1.0 KeyPackage Reference",
            &raw,
        )?))
    }
}
