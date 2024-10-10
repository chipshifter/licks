use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::mls::crypto::{cipher_suite::CipherSuite, provider::CryptoProvider};
use crate::mls::framing::{GroupInfo, GroupSecrets};
use crate::mls::key_package::KeyPackageRef;
use crate::mls::key_schedule::extract_welcome_secret;
use crate::mls::ratchet_tree::HPKECiphertext;
use crate::mls::utilities::error::{Error, Result};
use crate::mls::utilities::serde::{
    deserialize_opaque_vec, deserialize_vector, serialize_opaque_vec, serialize_vector,
    Deserializer, Serializer,
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Welcome {
    pub(crate) cipher_suite: CipherSuite,
    pub(crate) secrets: Vec<EncryptedGroupSecrets>,
    pub(crate) encrypted_group_info: Bytes,
}

impl Deserializer for Welcome {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        if buf.remaining() < 2 {
            return Err(Error::BufferTooSmall);
        }
        let cipher_suite = buf.get_u16().into();

        let mut secrets = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            secrets.push(EncryptedGroupSecrets::deserialize(b)?);
            Ok(())
        })?;

        let encrypted_group_info = deserialize_opaque_vec(buf)?;

        Ok(Self {
            cipher_suite,
            secrets,
            encrypted_group_info,
        })
    }
}

impl Serializer for Welcome {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        buf.put_u16(self.cipher_suite.into());
        serialize_vector(
            self.secrets.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.secrets[i].serialize(b) },
        )?;
        serialize_opaque_vec(&self.encrypted_group_info, buf)
    }
}

impl Welcome {
    /// Return the encrypted group secrets in this Welcome message.
    pub fn secrets(&self) -> &[EncryptedGroupSecrets] {
        self.secrets.as_ref()
    }

    /// Find `EncryptedGroupSecrets` based on a `KeyPackageRef`
    pub fn find_secret(&self, r: &KeyPackageRef) -> Option<&EncryptedGroupSecrets> {
        for (i, sec) in self.secrets.iter().enumerate() {
            if &sec.new_member == r {
                return Some(&self.secrets[i]);
            }
        }
        None
    }

    pub(crate) fn decrypt_group_secrets(
        &self,
        crypto_provider: &impl CryptoProvider,
        r: &KeyPackageRef,
        init_key_priv: &[u8],
    ) -> Result<GroupSecrets> {
        if let Some(sec) = self.find_secret(r) {
            let raw_group_secrets = crypto_provider.decrypt_with_label(
                self.cipher_suite,
                init_key_priv,
                b"Welcome",
                &self.encrypted_group_info,
                &sec.encrypted_group_secrets.kem_output,
                &sec.encrypted_group_secrets.ciphertext,
            )?;

            Ok(GroupSecrets::deserialize_exact(&raw_group_secrets)?)
        } else {
            Err(Error::EncryptedGroupSecretsNotFoundForProvidedKeyPackageRef)
        }
    }

    pub(crate) fn extract_key_and_nonce(
        welcome_secret: Bytes,
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
    ) -> Result<(Bytes, Bytes)> {
        let aead_nonce_size = crypto_provider.hpke(cipher_suite)?.aead_nonce_size();
        let welcome_nonce = crypto_provider.expand_with_label(
            cipher_suite,
            &welcome_secret,
            b"nonce",
            &[],
            aead_nonce_size,
        )?;

        let aead_key_size = crypto_provider.hpke(cipher_suite)?.aead_key_size();
        let welcome_key = crypto_provider.expand_with_label(
            cipher_suite,
            &welcome_secret,
            b"key",
            &[],
            aead_key_size,
        )?;

        Ok((welcome_key, welcome_nonce))
    }

    pub(crate) fn decrypt_group_info(
        &self,
        crypto_provider: &impl CryptoProvider,
        joiner_secret: &[u8],
        psk_secret: &[u8],
    ) -> Result<GroupInfo> {
        let welcome_secret = extract_welcome_secret(
            crypto_provider,
            self.cipher_suite,
            joiner_secret,
            psk_secret,
        )?;

        let (welcome_key, welcome_nonce) =
            Self::extract_key_and_nonce(welcome_secret, crypto_provider, self.cipher_suite)?;

        let raw_group_info = crypto_provider.hpke(self.cipher_suite)?.aead_open(
            &welcome_key,
            &welcome_nonce,
            &self.encrypted_group_info,
            &[],
        )?;

        GroupInfo::deserialize_exact(&raw_group_info)
    }
}

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct EncryptedGroupSecrets {
    new_member: KeyPackageRef,
    encrypted_group_secrets: HPKECiphertext,
}

impl Deserializer for EncryptedGroupSecrets {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let new_member = KeyPackageRef::deserialize(buf)?;
        let encrypted_group_secrets = HPKECiphertext::deserialize(buf)?;

        Ok(Self {
            new_member,
            encrypted_group_secrets,
        })
    }
}

impl Serializer for EncryptedGroupSecrets {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.new_member.serialize(buf)?;
        self.encrypted_group_secrets.serialize(buf)
    }
}

impl EncryptedGroupSecrets {
    /// Create a new `EncryptedGroupSecrets`
    pub fn new(new_member: KeyPackageRef, encrypted_group_secrets: HPKECiphertext) -> Self {
        Self {
            new_member,
            encrypted_group_secrets,
        }
    }

    /// Return `KeyPackageRef` of encrypted group secrets
    pub fn new_member(&self) -> &KeyPackageRef {
        &self.new_member
    }

    /// Return encrypted group secrets
    pub fn encrypted_group_secrets(&self) -> &HPKECiphertext {
        &self.encrypted_group_secrets
    }
}
