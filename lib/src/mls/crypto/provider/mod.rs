//! [RFC9420 Sec.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-5) `CryptoProvider` trait and
//! implementations that provide the cryptographic primitives to be used in group key computations.

#[cfg(test)]
mod provider_test;

mod key_store;
mod rust;

pub use self::rust::RustCryptoProvider;

use crate::crypto::rng::get_rng;
use crate::mls::crypto::{
    cipher_suite::CipherSuite, serialize_opaque_vec, Aead, Buf, Deserializer, Error, Kdf, Kem,
    Result, Serializer,
};

use crate::mls::crypto::key_pair::{HPKEKeyPair, SignatureKeyPair};
use bytes::{BufMut, Bytes, BytesMut};
use hpke::{Deserializable, Serializable};

/// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) MLS prefix string - "MLS 1.0 "
const MLS_PREFIX: &str = "MLS 1.0 ";

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) `HashScheme`
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub enum HashScheme {
    #[default]
    SHA256,
}

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) `HpkeSuite`
///
/// It is an HPKE cipher suite consisting of a KEM, KDF, and AEAD algorithm.
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub struct HpkeSuite {
    pub kem: Kem,
    pub kdf: Kdf,
    pub aead: Aead,
}

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) `SignatureScheme`
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum SignatureScheme {
    #[default]
    /// ED25519
    ED25519 = 0x0807,
}

impl Deserializer for SignatureScheme {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let v = buf.get_u16();
        match v {
            0x0807 => Ok(SignatureScheme::ED25519),
            _ => Err(Error::InvalidSignatureSchemeValue(v)),
        }
    }
}

impl Serializer for SignatureScheme {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(*self as u16);
        Ok(())
    }
}

/// `KeyStore` trait provides the CRUD operations of Key
pub trait KeyStore: Send + Sync {
    fn store(&self, key: &Bytes, val: &Bytes) -> Result<()>;
    fn retrieve(&self, key: &Bytes) -> Option<Bytes>;
    fn delete(&self, key: &Bytes) -> Option<Bytes>;
}

/// Rand trait provides randomness
pub trait Rand: Send + Sync {
    fn fill(&self, buf: &mut [u8]) -> Result<()>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Hash trait provides
/// hash algorithm and Message Authentication Code (MAC) algorithm
pub trait Hash: Send + Sync {
    /// hash size
    fn size(&self) -> usize;

    /// A hash algorithm
    fn digest(&self, data: &[u8]) -> Bytes;

    /// A Message Authentication Code (MAC) algorithm
    fn mac(&self, key: &[u8], message: &[u8]) -> Bytes;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Hpke trait provides
/// Key Derivation Function (KDF) algorithm and Authenticated Encryption with Associated Data (AEAD)
/// algorithm
pub trait Hpke: Send + Sync {
    /// Returns HPKE suite
    fn hpke_suite(&self) -> HpkeSuite;

    /// Generate a new HPKE key pair
    fn kem_derive_key_pair(&self, ikm: &[u8]) -> Result<HPKEKeyPair>;

    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Expand a pseudorandom key
    /// using optional string info into length bytes of output keying material.
    fn kdf_expand(&self, secret: &[u8], info: &[u8], length: u16) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Extract a pseudorandom key
    /// of fixed length Nh bytes from input keying material and an optional byte string salt.
    fn kdf_extract(&self, secret: &[u8], salt: &[u8]) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The output size of the
    /// Extract function in bytes.
    fn kdf_extract_size(&self) -> u16;

    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The length in bytes of
    /// a nonce for this algorithm.
    fn aead_nonce_size(&self) -> u16;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) The length in bytes of
    /// a key for this algorithm.
    fn aead_key_size(&self) -> u16;

    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Decrypt ciphertext using
    /// associated data with symmetric key and nonce, returning plaintext message
    fn aead_open(
        &self,
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes>;
    /// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html#section-4) Encrypt and authenticate
    /// plaintext with associated data aad using symmetric key and nonce, yielding ciphertext
    fn aead_seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<Bytes>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Signature trait provides
/// signature algorithm
pub trait Signature: Send + Sync {
    /// Generate a new signature key pair
    fn signature_key_pair(&self) -> Result<SignatureKeyPair>;

    /// Returns signature scheme
    fn signature_scheme(&self) -> SignatureScheme;

    /// Sign the message with the provided `sign_key`
    fn sign(&self, sign_key: &[u8], message: &[u8]) -> Result<Bytes>;

    /// Verify the message with the provided public key and signature
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()>;
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) `CryptoProvider` trait
/// specifies the cryptographic primitives to be used in group key computations
pub trait CryptoProvider {
    /// Check whether the cipher suite is supported or not
    fn supports(&self, cipher_suite: CipherSuite) -> bool;

    /// Return supported cipher suites
    fn supported(&self) -> Vec<CipherSuite>;

    /// Derive `KeyStore` trait object
    fn key_store(&self) -> &dyn KeyStore;

    /// Derive Hash trait object based on the given cipher suite
    fn hash(&self, cipher_suite: CipherSuite) -> Result<&dyn Hash>;

    /// Derive Hpke trait object based on the given cipher suite
    fn hpke(&self, cipher_suite: CipherSuite) -> Result<&dyn Hpke>;

    /// Derive Signature trait object based on the given cipher suite
    fn signature(&self, cipher_suite: CipherSuite) -> Result<&dyn Signature>;

    /// HMAC based sign based on the given cipher suite
    fn sign_mac(&self, cipher_suite: CipherSuite, key: &[u8], message: &[u8]) -> Result<Bytes> {
        // All cipher suites use HMAC
        Ok(self.hash(cipher_suite)?.mac(key, message))
    }

    /// HMAC based verify based on the given cipher suite
    fn verify_mac(
        &self,
        cipher_suite: CipherSuite,
        key: &[u8],
        message: &[u8],
        tag: &[u8],
    ) -> Result<()> {
        if tag == self.sign_mac(cipher_suite, key, message)?.as_ref() {
            Ok(())
        } else {
            Err(Error::VerifyConfirmationTagFailed)
        }
    }

    /// [RFC9420 Sec.5.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.2) Hash-Based Identifiers
    fn ref_hash(&self, cipher_suite: CipherSuite, label: &[u8], value: &[u8]) -> Result<Bytes> {
        let mut buf = BytesMut::new();
        serialize_opaque_vec(label, &mut buf)?;
        serialize_opaque_vec(value, &mut buf)?;
        let input = buf.freeze();
        let h = self.hash(cipher_suite)?;
        Ok(h.digest(&input))
    }

    /// Expand secret with label
    fn expand_with_label(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        length: u16,
    ) -> Result<Bytes> {
        let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
        mls_label.extend_from_slice(label);

        let mut buf = BytesMut::new();
        buf.put_u16(length);
        serialize_opaque_vec(&mls_label, &mut buf)?;
        serialize_opaque_vec(context, &mut buf)?;
        let info = buf.freeze();
        self.hpke(cipher_suite)?.kdf_expand(secret, &info, length)
    }

    /// Derive secret with label
    fn derive_secret(
        &self,
        cipher_suite: CipherSuite,
        secret: &[u8],
        label: &[u8],
    ) -> Result<Bytes> {
        let length = self.hpke(cipher_suite)?.kdf_extract_size();
        self.expand_with_label(cipher_suite, secret, label, &[], length)
    }

    /// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) Sign message with label
    fn sign_with_label(
        &self,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        label: &[u8],
        content: &[u8],
    ) -> Result<Bytes> {
        let sign_content = mls_prefix_label_data(label, content)?;
        self.signature(cipher_suite)?.sign(sign_key, &sign_content)
    }

    /// [RFC9420 Sec.5.1.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.2) Verify message with label
    fn verify_with_label(
        &self,
        cipher_suite: CipherSuite,
        verify_key: &[u8],
        label: &[u8],
        content: &[u8],
        sign_value: &[u8],
    ) -> Result<()> {
        let sign_content = mls_prefix_label_data(label, content)?;
        self.signature(cipher_suite)?
            .verify(verify_key, &sign_content, sign_value)
    }

    /// [RFC9420 Sec.5.1.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3) Encrypt message with label
    fn encrypt_with_label(
        &self,
        cipher_suite: CipherSuite,
        public_key: &[u8],
        label: &[u8],
        context: &[u8],
        plaintext: &[u8],
    ) -> Result<(Bytes, Bytes)> {
        let info = mls_prefix_label_data(label, context)?;
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                let public_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(public_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let (kem_output, mut encryption_context) =
                    hpke::setup_sender::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                        _,
                    >(&hpke::OpModeS::Base, &public_key, &info, &mut get_rng())
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                let ciphertext = encryption_context
                    .seal(plaintext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;
                Ok((
                    Bytes::from(kem_output.to_bytes().to_vec()),
                    Bytes::from(ciphertext),
                ))
            }
            CipherSuite::Unknown(_) => Err(Error::UnsupportedCipherSuite),
        }
    }

    /// [RFC9420 Sec.5.1.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.3) Decrypt message with label
    fn decrypt_with_label(
        &self,
        cipher_suite: CipherSuite,
        private_key: &[u8],
        label: &[u8],
        context: &[u8],
        kem_output: &[u8],
        ciphertext: &[u8],
    ) -> Result<Bytes> {
        let info = mls_prefix_label_data(label, context)?;
        match cipher_suite {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => {
                let private_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(private_key)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;
                let encapped_key =
                    <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(kem_output)
                        .map_err(|err| Error::HpkeError(err.to_string()))?;

                let mut decryption_context =
                    hpke::setup_receiver::<
                        hpke::aead::AesGcm128,
                        hpke::kdf::HkdfSha256,
                        hpke::kem::X25519HkdfSha256,
                    >(&hpke::OpModeR::Base, &private_key, &encapped_key, &info)
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                let plaintext = decryption_context
                    .open(ciphertext, &[])
                    .map_err(|err| Error::HpkeError(err.to_string()))?;

                Ok(Bytes::from(plaintext))
            }
            CipherSuite::Unknown(_) => Err(Error::UnsupportedCipherSuite),
        }
    }
}

fn mls_prefix_label_data(label: &[u8], data: &[u8]) -> Result<Bytes> {
    let mut mls_label = MLS_PREFIX.as_bytes().to_vec();
    mls_label.extend_from_slice(label);

    let mut buf = BytesMut::new();
    serialize_opaque_vec(&mls_label, &mut buf)?;
    serialize_opaque_vec(data, &mut buf)?;
    Ok(buf.freeze())
}
