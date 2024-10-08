//! Implementations for server, account, and device certificates using ed25519 for the signature type.

use ed25519_dalek::ed25519::signature::Signer;
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, hash::Hash};

use crate::{
    api::{connection::proto, server::Server},
    crypto::rng::get_rng,
    error::ProtoError,
    identifiers::{AccountId, DeviceId, LicksIdentifier},
};

use super::{Certificate, CertificateChain, CertificateError, SerializedChain};

pub(super) type Ed25519Signature = ed25519_dalek::Signature;
pub(super) type Ed25519SecretKey = ed25519_dalek::SigningKey;
pub(super) type Ed25519PublicKey = ed25519_dalek::VerifyingKey;

#[derive(Debug, Clone, Eq, Serialize, Deserialize)]
pub struct Ed25519CertificateChain {
    pub(super) account_cert: Box<Ed25519AccountCert>,
    pub(super) account_to_device_sig: Box<Ed25519Signature>,
    pub(super) device_cert: Box<Ed25519DeviceCert>,
}

impl PartialEq for Ed25519CertificateChain {
    fn eq(&self, other: &Self) -> bool {
        self.account_cert.account_id == other.account_cert.account_id
            && self.account_cert.server == other.account_cert.server
            && self.device_cert.device_id == other.device_cert.device_id
    }
}

impl Hash for Ed25519CertificateChain {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.account_cert.account_id.hash(state);
        self.account_cert.server.hash(state);
        self.device_cert.device_id.hash(state);
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ed25519CertificateChainSecret {
    pub public_chain: Ed25519CertificateChain,
    pub account_secret: Box<Ed25519SecretKey>,
    pub device_secret: Box<Ed25519SecretKey>,
}

impl Debug for Ed25519CertificateChainSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519CertificateChainSecret")
            .field("public_chain", &self.public_chain)
            .finish_non_exhaustive()
    }
}

impl Hash for Ed25519CertificateChainSecret {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.public_chain.hash(state);
    }
}

impl Ed25519CertificateChainSecret {
    pub fn new(
        account_cert: Ed25519AccountCert,
        account_secret: Ed25519SecretKey,
        device_cert: Ed25519DeviceCert,
        device_secret: Ed25519SecretKey,
    ) -> Self {
        let account_to_device_sig = account_secret.sign(&device_cert.to_bytes());
        let public_chain = Ed25519CertificateChain {
            account_cert: Box::new(account_cert),
            account_to_device_sig: Box::new(account_to_device_sig),
            device_cert: Box::new(device_cert),
        };

        Self {
            public_chain,
            account_secret: Box::new(account_secret),
            device_secret: Box::new(device_secret),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let proto = proto::Ed25519CertificateChainSecret {
            public: Some(self.public_chain.clone().serialize().into()),
            account_secret: self.account_secret.to_bytes().to_vec(),
            device_secret: self.device_secret.to_bytes().to_vec(),
        };

        proto.encode_to_vec()
    }

    // Because we want to return the `Ed25519CertificateChainSecret` type,
    // we need to have our own deserializer that specifically returns Ed25519
    // credentials instead of type-erased credentials (that may not be using Ed25519
    // as the signature scheme)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtoError> {
        let proto = proto::Ed25519CertificateChainSecret::decode(bytes).map_err(|_| ProtoError)?;

        let public: SerializedChain = proto
            .public
            .ok_or(ProtoError)?
            .try_into()
            .map_err(|_| ProtoError)?;

        // NOTE: In the future where we have more `SerializedChain` types
        // we will change this to a `match` and potentially return a ProtoError
        // if we end up not having an `Ed25519Chain`
        let SerializedChain::Ed25519Chain(ed25519_public) = public;

        Ok(Self {
            public_chain: ed25519_public,
            account_secret: Box::new(Ed25519SecretKey::from_bytes(
                &proto.account_secret.try_into().map_err(|_| ProtoError)?,
            )),
            device_secret: Box::new(Ed25519SecretKey::from_bytes(
                &proto.device_secret.try_into().map_err(|_| ProtoError)?,
            )),
        })
    }
}

impl super::CertificateChainSecret for Ed25519CertificateChainSecret {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        self.device_secret.sign(message).to_vec()
    }

    /// Returns a serialized copy of the public certificate chain.
    ///
    /// NOTE: This performs a `Clone`.
    fn serialized(&self) -> super::SerializedChain {
        self.public_chain.clone().serialize()
    }
}

impl super::CertificateChain for Ed25519CertificateChain {
    fn get_server(&self) -> &Server {
        &self.account_cert.server
    }

    fn account_id(&self) -> &AccountId {
        &self.account_cert.account_id
    }

    fn device_id(&self) -> &DeviceId {
        &self.device_cert.device_id
    }

    fn verify_self(&self) -> Result<(), CertificateError> {
        self.account_cert.verify_self_signature()?;
        self.device_cert.verify_self_signature()?;
        self.account_cert
            .pub_key
            .verify_strict(&self.device_cert.to_bytes(), &self.account_to_device_sig)
            .map_err(|_| CertificateError::InvalidSignature)?;

        Ok(())
    }

    fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), CertificateError> {
        let signature =
            Ed25519Signature::from_slice(signature).map_err(|_| CertificateError::InvalidData)?;

        self.device_cert
            .pub_key
            .verify_strict(message, &signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }

    fn serialize(self) -> super::SerializedChain {
        super::SerializedChain::Ed25519Chain(self)
    }

    fn account_cert(&self) -> &impl Certificate {
        &*self.account_cert
    }

    fn device_cert(&self) -> &impl Certificate {
        &*self.device_cert
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519AccountCert {
    pub(super) server: Server,
    pub(super) account_id: AccountId,
    pub(super) pub_key: Ed25519PublicKey,
    pub(super) self_signature: Ed25519Signature,
}

impl Ed25519AccountCert {
    pub fn serialize(self) -> super::SerializedAccountCertificate {
        super::SerializedAccountCertificate::Ed25519(Box::new(self))
    }
}

impl Ed25519AccountCert {
    pub fn generate_keys() -> (Ed25519PublicKey, Ed25519SecretKey) {
        let mut rng = get_rng();
        let secret_key = Ed25519SecretKey::generate(&mut rng);
        let pub_key = secret_key.verifying_key();

        (pub_key, secret_key)
    }

    pub fn complete(
        pub_key: Ed25519PublicKey,
        secret_key: &mut Ed25519SecretKey,
        server: Server,
        account_id: AccountId,
    ) -> Self {
        let mut bytes: Vec<u8> = account_id.to_bytes().to_vec();
        bytes.append(&mut server.clone().to_vec());
        bytes.append(&mut pub_key.to_bytes().to_vec());

        let self_signature = secret_key.sign(&bytes);

        Self {
            server,
            account_id,
            pub_key,
            self_signature,
        }
    }

    pub fn generate(server: Server, account_id: AccountId) -> (Self, Ed25519SecretKey) {
        let (public_key, mut secret_key) = Self::generate_keys();
        let public_cert = Self::complete(public_key, &mut secret_key, server, account_id);

        (public_cert, secret_key)
    }
}

impl super::Certificate for Ed25519AccountCert {
    fn get_scheme(&self) -> super::SignatureScheme {
        super::SignatureScheme::Ed25519
    }

    fn verify_self_signature(&self) -> Result<(), CertificateError> {
        let mut bytes: Vec<u8> = self.account_id.to_bytes().to_vec();
        bytes.append(&mut self.server.clone().to_vec());
        bytes.append(&mut self.pub_key.to_bytes().to_vec());

        self.pub_key
            .verify_strict(&bytes, &self.self_signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }

    fn pub_key_bytes(&self) -> Vec<u8> {
        self.pub_key.to_bytes().to_vec()
    }

    fn to_proto(&self) -> proto::Certificate {
        let mut data: Vec<u8> = self.account_id.to_bytes().to_vec();
        data.append(&mut self.server.to_vec());

        proto::Certificate {
            scheme: proto::SignatureScheme::Ed25519.into(),
            public_key: self.pub_key.to_bytes().to_vec(),
            self_signature_of_inner: self.self_signature.to_vec(),
            data,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519DeviceCert {
    pub(super) device_id: DeviceId,
    pub(super) pub_key: Ed25519PublicKey,
    pub(super) self_signature: Ed25519Signature,
}

impl Ed25519DeviceCert {
    pub fn generate(device_id: DeviceId) -> (Self, Ed25519SecretKey) {
        let mut rng = get_rng();
        let secret_key = Ed25519SecretKey::generate(&mut rng);
        let pub_key = secret_key.verifying_key();

        let mut bytes: Vec<u8> = device_id.to_bytes().to_vec();
        bytes.append(&mut pub_key.to_bytes().to_vec());

        let self_signature = secret_key.sign(&bytes);

        let public_cert = Self {
            device_id,
            pub_key,
            self_signature,
        };

        (public_cert, secret_key)
    }
}

impl super::Certificate for Ed25519DeviceCert {
    fn get_scheme(&self) -> super::SignatureScheme {
        super::SignatureScheme::Ed25519
    }

    fn verify_self_signature(&self) -> Result<(), CertificateError> {
        let mut bytes: Vec<u8> = self.device_id.to_bytes().to_vec();
        bytes.append(&mut self.pub_key.to_bytes().to_vec());

        self.pub_key
            .verify_strict(&bytes, &self.self_signature)
            .map_err(|_| CertificateError::InvalidSignature)
    }

    fn pub_key_bytes(&self) -> Vec<u8> {
        self.pub_key.to_bytes().to_vec()
    }

    fn to_proto(&self) -> proto::Certificate {
        let data: Vec<u8> = self.device_id.to_bytes().to_vec();

        proto::Certificate {
            scheme: proto::SignatureScheme::Ed25519.into(),
            public_key: self.pub_key.to_bytes().to_vec(),
            self_signature_of_inner: self.self_signature.to_vec(),
            data,
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::crypto::certificates::{CertificateChain, CertificateChainSecret, SerializedChain};

    use super::*;

    #[test]
    pub fn test_ed25519_chain() {
        let (account_cert, account_secret) =
            Ed25519AccountCert::generate(Server::localhost(), AccountId::generate_id());
        let (device_cert, device_secret) = Ed25519DeviceCert::generate(DeviceId::generate_id());

        let chain_secret = Ed25519CertificateChainSecret::new(
            account_cert,
            account_secret,
            device_cert,
            device_secret,
        );

        let chain = chain_secret.public_chain.clone();

        assert!(
            chain.verify_self().is_ok(),
            "Correctly generated chain should always be valid"
        );

        // Serialization round trip
        let chain_bytes = chain.clone().to_bytes();
        let serialized_chain =
            SerializedChain::from_bytes(&chain_bytes).expect("Serialization round-trip works");

        let other_serialized_chain = chain_secret.serialized();
        assert_eq!(
            serialized_chain, other_serialized_chain,
            ".serialized() and .to_bytes() should serialize things the same way"
        );

        let parsed_chain = serialized_chain.verify().expect("our certificate is valid");

        assert_eq!(chain.get_server(), parsed_chain.get_server());
        assert_eq!(chain.account_id(), parsed_chain.account_id());
        assert_eq!(chain.device_id(), parsed_chain.device_id());
        assert_eq!(chain.to_bytes(), parsed_chain.to_bytes());
    }

    #[test]
    pub fn test_fake_ed25519_chain() {
        todo!("Verify that invalid signatures don't get parsed as correct chains");
    }
}
