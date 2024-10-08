//! Utility functions for deriving a blinded address.
//! Could be from a group or a single person. Currently the work is being done on groups.
//! See documentation at "docs/lib/API/Blinded\ Addresses.md" for more info.
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(thiserror::Error, Debug, PartialEq)]
#[error("The blinded address verification failed")]
pub struct BlindedAddressVerificationError;

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy, PartialOrd, Ord)]
pub struct BlindedAddressPublic(pub(crate) [u8; 32]);

impl BlindedAddressPublic {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Hash, Clone, Copy)]
pub struct BlindedAddressSecret {
    pub(crate) secret: [u8; 32],
    pub public: BlindedAddressPublic,
}

impl BlindedAddressSecret {
    pub fn from_group_secret(secret_group_key: &[u8]) -> Self {
        // No salt or randomness is introduced inside the KDF.
        // We want the KDF to be predictable so that all members of the
        // group can generate the same address (necessary).
        let salt = None;
        let info = b"licks_blinded_address_v2";

        let hk = Hkdf::<Sha256>::new(salt, secret_group_key);
        let mut secret = [0u8; 32];
        hk.expand(info, &mut secret)
            .expect("32 is a valid length for Sha256 to output");

        let hash: [u8; 32] = Sha256::digest(secret).into();

        BlindedAddressSecret {
            secret,
            public: BlindedAddressPublic(hash),
        }
    }

    pub fn verify(self) -> Result<BlindedAddressPublic, BlindedAddressVerificationError> {
        let secret_hash: [u8; 32] = Sha256::digest(self.secret).into();

        if secret_hash.eq(&self.public.0) {
            Ok(self.public)
        } else {
            Err(BlindedAddressVerificationError)
        }
    }

    pub fn to_bytes(self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.secret);
        bytes[32..64].copy_from_slice(&self.public.0);

        bytes
    }

    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let (secret, public) = bytes.split_at(32);
        Self {
            secret: secret.try_into().expect("slice is 32 bytes long"),
            public: BlindedAddressPublic(public.try_into().expect("slice is 32 bytes long")),
        }
    }
}

pub mod test_utils {
    use super::BlindedAddressSecret;

    pub fn generate_blinded_address_random() -> BlindedAddressSecret {
        use crate::util::uuid::generate_uuid;

        BlindedAddressSecret::from_group_secret(generate_uuid().as_bytes())
    }

    pub fn generate_blinded_address_fake() -> BlindedAddressSecret {
        let one = generate_blinded_address_random();
        let two = generate_blinded_address_random();

        BlindedAddressSecret {
            secret: one.secret,
            public: two.public,
        }
    }
}

impl std::fmt::Display for BlindedAddressPublic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BlindedAddressPublic({:?})", &self.0)
    }
}

impl std::fmt::Display for BlindedAddressSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.public.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::blinded_address::test_utils::{
        generate_blinded_address_fake, generate_blinded_address_random,
    };

    use super::*;

    #[test]
    pub fn test_verify_blinded_group_address() {
        let ok = generate_blinded_address_random();

        assert_eq!(
            ok.verify(),
            Ok(ok.public),
            "The correct blinded address should have been successfully validated"
        );

        // frankenstein address
        let not_ok = generate_blinded_address_fake();

        assert_eq!(
            not_ok.verify(),
            Err(BlindedAddressVerificationError),
            "Forged blinded address with incorrect secret should have been rejected"
        );
    }

    #[test]
    pub fn test_display_blinded_address() {
        let secret_bytes = [1u8; 32];
        let public_bytes = [0u8; 32];

        let b = BlindedAddressSecret {
            secret: secret_bytes,
            public: BlindedAddressPublic(public_bytes),
        };

        assert_eq!(
            "BlindedAddressPublic([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])",
            format!("{}", b.public),
            "BlindedAddressPublic should only display public value"
        );
        assert_eq!(
            "BlindedAddressPublic([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])",
            format!("{b}"),
            "BlindedAddressSecret should only display public value and not the secret"
        );
    }
}
