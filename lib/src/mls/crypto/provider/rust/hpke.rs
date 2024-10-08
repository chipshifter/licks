use aes_gcm::{
    aead::{consts::U12, AeadInPlace},
    Aes128Gcm, Key as AesKey, Nonce,
};
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use hpke::{Kem, Serializable};
use sha2::Sha256;

use crate::mls::crypto::key_pair::HPKEKeyPair;
use crate::mls::crypto::provider::HpkeSuite;
use crate::mls::crypto::{provider, Aead, Error, Kdf, Key, Result};

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct HpkeSuiteWrapper(pub(super) HpkeSuite);

impl provider::Hpke for HpkeSuiteWrapper {
    fn hpke_suite(&self) -> HpkeSuite {
        self.0
    }

    fn kem_derive_key_pair(&self, ikm: &[u8]) -> Result<HPKEKeyPair> {
        match self.0.kem {
            provider::Kem::KEM_X25519_HKDF_SHA256 => {
                let (private_key, public_key) = hpke::kem::X25519HkdfSha256::derive_keypair(ikm);
                Ok(HPKEKeyPair {
                    private_key: Key(Bytes::from(private_key.to_bytes().to_vec())),
                    public_key: Key(Bytes::from(public_key.to_bytes().to_vec())),
                })
            }
        }
    }

    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes> {
        let mut out = vec![0u8; length as usize];

        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => {
                let hkdf = Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
                hkdf.expand(info, &mut out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;
            }
        };

        Ok(Bytes::from(out))
    }

    fn kdf_extract(&self, secret: &[u8], salt: &[u8]) -> Result<Bytes> {
        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => {
                let mut m = Hmac::<Sha256>::new_from_slice(salt)?;
                m.update(secret);
                Ok(Bytes::from(m.finalize().into_bytes().to_vec()))
            }
        }
    }

    fn kdf_extract_size(&self) -> u16 {
        match self.0.kdf {
            Kdf::KDF_HKDF_SHA256 => 32,
        }
    }

    // key_size returns the size in bytes of the keys used by the AEAD cipher.
    fn aead_key_size(&self) -> u16 {
        match self.0.aead {
            Aead::AEAD_AES128GCM => 16,
        }
    }

    // nonce_size returns the size in bytes of the nonce used by the AEAD cipher.
    fn aead_nonce_size(&self) -> u16 {
        match self.0.aead {
            Aead::AEAD_AES128GCM => 12,
        }
    }

    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes> {
        use aes_gcm::KeyInit;
        match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key: &AesKey<Aes128Gcm> = key.into();
                let nonce: &Nonce<U12> = nonce.into();

                let cipher = Aes128Gcm::new(key);
                let mut in_out = ciphertext.to_vec();
                cipher
                    .decrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
        }
    }

    fn aead_seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes> {
        use aes_gcm::KeyInit;
        match self.0.aead {
            Aead::AEAD_AES128GCM => {
                let key: &AesKey<Aes128Gcm> = key.into();
                let nonce: &Nonce<U12> = nonce.into();

                let cipher = Aes128Gcm::new(key);
                let mut in_out = plaintext.to_vec();
                cipher
                    .encrypt_in_place(nonce, additional_data, &mut in_out)
                    .map_err(|err| Error::RustCryptoError(err.to_string()))?;

                Ok(Bytes::from(in_out))
            }
        }
    }
}
