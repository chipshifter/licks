use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::rng::random_bytes;

/// A randomly generated, unique token.
///
/// The commitment [`ListenerCommitment`] is sent to the server
/// when requesting to listen to a particular address.
///
/// When a user wants to stop listening to an address, they send
/// [`ListenerToken`], which allows the server to verify that the
/// client is the owner of the (previously) secret value that generated
/// the commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerToken(pub [u8; 32]);

impl Default for ListenerToken {
    fn default() -> Self {
        Self(random_bytes::<32>())
    }
}

impl ListenerToken {
    pub fn commitment(&self) -> ListenerCommitment {
        let mut hasher = Sha256::new();

        hasher.update(&self.0);

        ListenerCommitment(hasher.finalize().into())
    }

    pub fn validate_commitment(&self, commitment: ListenerCommitment) -> bool {
        self.commitment() == commitment
    }
}

/// A public value associated with a listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerCommitment(pub [u8; 32]);

impl From<ListenerCommitment> for Vec<u8> {
    fn from(value: ListenerCommitment) -> Self {
        value.0.to_vec()
    }
}

impl From<ListenerToken> for Vec<u8> {
    fn from(value: ListenerToken) -> Self {
        value.0.to_vec()
    }
}

impl TryFrom<Vec<u8>> for ListenerCommitment {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| ())?))
    }
}

impl TryFrom<Vec<u8>> for ListenerToken {
    type Error = ();

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into().map_err(|_| ())?))
    }
}
