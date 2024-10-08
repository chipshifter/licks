//! [RFC9420 Sec.5](https://www.rfc-editor.org/rfc/rfc9420.html#section-5) Cryptographic Objects
#[cfg(test)]
mod crypto_test;

use bytes::{Buf, BufMut, Bytes};
use std::ops::Deref;

use crate::mls::utilities::{
    error::{Error, Result},
    serde::{deserialize_opaque_vec, serialize_opaque_vec, Deserializer, Serializer},
};

pub mod cipher_suite;
pub mod config;
pub mod credential;
pub mod key_pair;
pub mod provider;

#[derive(Default, Debug, Clone, Eq, PartialEq, Hash)]
pub struct Key(Bytes);

impl Deref for Key {
    type Target = Bytes;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Deserializer for Key {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        Ok(Key(deserialize_opaque_vec(buf)?))
    }
}

impl Serializer for Key {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.0, buf)
    }
}

/// [RFC9420 Sec.5.1.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.1) HPKE public keys are
/// opaque values in a format defined by the underlying protocol (see Section 4 of
/// [RFC9180](https://www.rfc-editor.org/rfc/rfc9180.html) for more information).
pub type HPKEPublicKey = Key;
pub type HPKEPrivateKey = Key;

/// [RFC9420 Sec.5.1.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1.1) Signature public keys
/// are likewise represented as opaque values in a format defined by the cipher suite's signature scheme.
pub type SignaturePublicKey = Key;
pub type SignaturePrivateKey = Key;

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Key Encapsulation
/// Mechanism (KEM) of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kem {
    #[default]
    /// `KEM_X25519_HKDF_SHA256` is a KEM using X25519 Diffie-Hellman function
    /// and HKDF with SHA-256.
    KEM_X25519_HKDF_SHA256 = 0x20,
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Key Derivation Function
/// (KDF) of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Kdf {
    #[default]
    /// `KDF_HKDF_SHA256` is a KDF using HKDF with SHA-256.
    KDF_HKDF_SHA256 = 0x01,
}

/// [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1)  Authenticated Encryption
/// with Associated Data (AEAD) encryption algorithm of HPKE parameters
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u16)]
pub enum Aead {
    #[default]
    /// `AEAD_AES128GCM` is AES-128 block cipher in Galois Counter Mode (GCM).
    AEAD_AES128GCM = 0x01,
}
