//! "Blinded Addresses" is the name of the mechanism used to store MLS messages
//! on the server.
//!
//! ### Introduction to Blinded Addresss
//!
//! The goal of Blinded Addresses is to allow messages being stored on the server, in
//! a way that the server without revealing any information as to what group these messages
//! belong for.
//!
//! The idea behind it is simple: users in a group (during a specific epoch K) all share a
//! group secret S. This secret is not known to anyone outside to group. Then, using this secret S,
//! a blinded address secret key is generated as SK = KDF(S). Note that the KDF properties guarantee
//! that knowledge of SK does not reveal S.
//!
//! This blinded address key can then be used as an Ed25519 secret key, from which we can dedude
//! the public key PK. To send a message M to the server, the user sends (M, PK, Sig_M) with Sig_M
//! an Ed25519 signature of M, which can be verified by the server using PK. If the signature is valid,
//! then the server simply stores the message into the blinded address PK.
//!
//! If and only if a user knows S, then they are able to generate a (M, PK, Sig_M) such that PK can be
//! retrieved from S. Therefore, all users in a group knowing S can access the blinded address by computing
//! PK and retrieving the messages (currently using an unauthenticated request).
//!
//! The server has no knowledge of the group secret S, and PK addresses are "random".
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use signature::SignerMut;

use crate::{api::proto, error::ProtoError};

#[derive(thiserror::Error, Debug, PartialEq)]
#[error("The blinded address verification failed")]
pub struct BlindedAddressVerificationError;

/// A public proof that is used to send a message to the server, which
/// can verify that the user knows the secret value of the blinded address
/// they're sending their message to, by checking the proof's signature.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct BlindedAddressProof {
    pub ba_public: BlindedAddressPublic,
    pub message: Vec<u8>,
    pub signature: Vec<u8>,
}

impl BlindedAddressProof {
    pub fn verify(
        self,
    ) -> Result<(BlindedAddressPublic, Vec<u8>), BlindedAddressVerificationError> {
        let ed25519_signature = ed25519_dalek::Signature::from_slice(&self.signature)
            .map_err(|_| BlindedAddressVerificationError)?;

        let ed25519_public = ed25519_dalek::VerifyingKey::from_bytes(&self.ba_public.0)
            .map_err(|_| BlindedAddressVerificationError)?;

        match ed25519_public.verify_strict(&self.message, &ed25519_signature) {
            Ok(()) => Ok((self.ba_public, self.message)),
            Err(_) => Err(BlindedAddressVerificationError),
        }
    }
}

impl From<BlindedAddressProof> for proto::BlindedAddressProof {
    fn from(value: BlindedAddressProof) -> Self {
        Self {
            ba_public: Some(value.ba_public.into()),
            message: value.message,
            signature: value.signature,
        }
    }
}

impl TryFrom<proto::BlindedAddressProof> for BlindedAddressProof {
    type Error = ProtoError;

    fn try_from(value: proto::BlindedAddressProof) -> Result<Self, Self::Error> {
        Ok(Self {
            ba_public: value.ba_public.ok_or(ProtoError)?.try_into()?,
            message: value.message,
            signature: value.signature,
        })
    }
}

pub const BLINDED_ADDRESS_PUBLIC_LENGTH: usize = ed25519_dalek::PUBLIC_KEY_LENGTH;

/// The blinded address's public value (corresponding to PK, the ed25519's public key)
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone, Copy, Hash, PartialOrd, Ord)]
pub struct BlindedAddressPublic(pub [u8; BLINDED_ADDRESS_PUBLIC_LENGTH]);

impl From<BlindedAddressPublic> for proto::BlindedAddressPublic {
    fn from(value: BlindedAddressPublic) -> Self {
        Self {
            value: value.0.to_vec(),
        }
    }
}

impl TryFrom<proto::BlindedAddressPublic> for BlindedAddressPublic {
    type Error = ProtoError;

    fn try_from(value: proto::BlindedAddressPublic) -> Result<Self, Self::Error> {
        Ok(Self(value.value.try_into().map_err(|_| ProtoError)?))
    }
}

/// The secret value of the blinded address, which can be used to generate proofs
/// (see [`BlindedAddressProof`]).
// Small note: PartialEq implementation is constant-time and handled by ed25519_dalek
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlindedAddressSecret {
    ed25519_secret: ed25519_dalek::SigningKey,
}

impl BlindedAddressSecret {
    pub fn from_group_secret(secret_group_key: &[u8]) -> Self {
        // No salt or randomness is introduced inside the KDF.
        // We want the KDF to be predictable so that all members of the
        // group can generate the same address (necessary).
        let salt = None;
        let info = b"licks_blinded_address_v3";

        let hk = Hkdf::<Sha256>::new(salt, secret_group_key);
        let mut secret = [0u8; 32];
        hk.expand(info, &mut secret)
            .expect("32 is a valid length for Sha256 to output");

        let ed25519_secret: ed25519_dalek::SigningKey = ed25519_dalek::SigningKey::from(secret);

        BlindedAddressSecret { ed25519_secret }
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.ed25519_secret.to_bytes()
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self {
            ed25519_secret: ed25519_dalek::SigningKey::from(bytes),
        }
    }

    pub fn to_public(&self) -> BlindedAddressPublic {
        BlindedAddressPublic(ed25519_dalek::VerifyingKey::from(&self.ed25519_secret).to_bytes())
    }

    pub fn create_proof(&mut self, message: Vec<u8>) -> BlindedAddressProof {
        let signature = self.ed25519_secret.sign(&message).to_vec();
        let ba_public = self.to_public();

        BlindedAddressProof {
            ba_public,
            message,
            signature,
        }
    }
}

impl std::fmt::Display for BlindedAddressPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ba_v3({:x?})", &self.0)
    }
}

impl std::fmt::Display for BlindedAddressSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.to_public().fmt(f)
    }
}

#[cfg(test)]
mod tests {

    use crate::crypto::rng::random_bytes;

    use super::*;

    #[test]
    // We test whether the generation on blinded addresses
    // is always the same if the group secret S is the same
    pub fn test_deterministic_blinded_address() {
        let random_group_secret = random_bytes::<16>();
        let ba_secret_1 = BlindedAddressSecret::from_group_secret(&random_group_secret);
        let ba_secret_2 = BlindedAddressSecret::from_group_secret(&random_group_secret);

        assert_eq!(
            ba_secret_1, ba_secret_2,
            "Blinded address secrets generated from the same group secret should be equal."
        );
    }

    #[test]
    pub fn test_verify_blinded_address() {
        let random_secret = random_bytes::<16>();
        let mut ba_secret = BlindedAddressSecret::from_group_secret(&random_secret);

        let message = b"hello";
        let proof = ba_secret.create_proof(message.to_vec());

        let mut fake_proof = proof.clone();
        fake_proof.message = b"other message".to_vec();

        assert!(
            proof.verify().is_ok(),
            "The correct blinded address should have been successfully validated"
        );

        assert!(
            fake_proof.verify().is_err(),
            "Forged message/incorrect signature should not be validated"
        );
    }
}
