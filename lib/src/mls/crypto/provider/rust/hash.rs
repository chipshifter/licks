use bytes::Bytes;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::mls::crypto::provider::HashScheme;

#[derive(Default, Debug, Copy, Clone, Eq, PartialEq)]
pub(super) struct HashSchemeWrapper(pub(super) HashScheme);

impl crate::mls::crypto::provider::Hash for HashSchemeWrapper {
    fn size(&self) -> usize {
        match self.0 {
            HashScheme::SHA256 => 32,
        }
    }

    fn digest(&self, data: &[u8]) -> Bytes {
        match self.0 {
            HashScheme::SHA256 => {
                let mut h = Sha256::new();
                h.update(data);
                Bytes::from(h.finalize().to_vec())
            }
        }
    }

    fn mac(&self, key: &[u8], message: &[u8]) -> Bytes {
        match self.0 {
            HashScheme::SHA256 => {
                let mut m =
                    Hmac::<Sha256>::new_from_slice(key).expect("hmac can take keys of any size");
                m.update(message);
                Bytes::from(m.finalize().into_bytes().to_vec())
            }
        }
    }
}
