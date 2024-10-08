use bytes::Bytes;
use signature::{Signer, Verifier};

use crate::crypto::rng::get_rng;
use crate::mls::crypto::{key_pair::SignatureKeyPair, provider::SignatureScheme, Key};
use crate::mls::utilities::error::{Error, Result};

#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct SignatureSchemeWrapper(pub(super) SignatureScheme);

impl crate::mls::crypto::provider::Signature for SignatureSchemeWrapper {
    fn signature_key_pair(&self) -> Result<SignatureKeyPair> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let signing_key =
                    ed25519_dalek::SigningKey::generate(&mut get_rng()).to_keypair_bytes();
                let (private_key, public_key) =
                    signing_key.split_at(ed25519_dalek::SECRET_KEY_LENGTH);
                Ok(SignatureKeyPair {
                    private_key: Key(Bytes::from(private_key.to_vec())),
                    public_key: Key(Bytes::from(public_key.to_vec())),
                    signature_scheme: self.0,
                })
            }
        }
    }

    fn signature_scheme(&self) -> SignatureScheme {
        self.0
    }

    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let private_key = ed25519_dalek::SigningKey::from_bytes(
                    &sign_key
                        .try_into()
                        .map_err(|_| Error::InvalidEd25519PrivateKey)?,
                );
                let signature: ed25519_dalek::Signature = private_key.sign(message);
                Ok(Bytes::from(signature.to_vec()))
            }
        }
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
        match self.0 {
            SignatureScheme::ED25519 => {
                let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(
                    &public_key
                        .try_into()
                        .map_err(|_| Error::InvalidEd25519PrivateKey)?,
                )?;
                let signature = ed25519_dalek::Signature::from_slice(signature)?;
                verifying_key.verify(message, &signature)?;
                Ok(())
            }
        }
    }
}
