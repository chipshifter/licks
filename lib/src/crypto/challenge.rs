//! Basic interactive challenge to authenticate clients to their registered server.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{api::connection::proto, error::ProtoError};

use super::{
    certificates::{CertificateChain, CertificateChainSecret, CertificateError, SerializedChain},
    rng::random_bytes,
};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
/// A "challenge", which is just random bytes generated by the server.
/// The client is then supposed to authenticate these bytes by signing them.
pub struct AuthChallenge(pub [u8; 32]);

impl AuthChallenge {
    /// Generate the challenge bytes. Used by the server.
    pub fn generate() -> Self {
        Self(random_bytes::<32>())
    }

    pub fn hash(&self, our_bytes: Self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.as_bytes());
        hasher.update(our_bytes.as_bytes());

        hasher.finalize().into()
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Accept the challenge by signing it safely. Used by the client, and
    /// the response is verified by the server.
    pub fn accept(self, cert_secret: &impl CertificateChainSecret) -> AuthChallengeResponse {
        // Generate our own extra random bytes
        let our_bytes = Self::generate();

        // Hash the two random bytes
        let hash = self.hash(our_bytes);

        // Sign the hash
        let device_signature_of_hash = cert_secret.sign(&hash);

        AuthChallengeResponse {
            chain: cert_secret.serialized(),
            client_bytes: our_bytes,
            device_signature_of_hash,
        }
    }
}

/// A response to an [`AuthChallenge`] generated by a client.
/// Anyone can verify this (in practice it's the server's job),
/// by verifying that:
///
/// 1 - The [`CertificateChain`] is valid
/// 2 - The bytes are signed by the chain
///
/// The bytes that are signed aren't the ones sent by the server.
/// Instead, they are a hash of the server's bytes and the client's bytes.
/// This is to prevent a dishonest server to send arbitrary bytes (such
/// as a payload) to the client who would try to sign it no matter what.
/// See issue #47
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthChallengeResponse {
    pub chain: SerializedChain,
    pub client_bytes: AuthChallenge,
    pub device_signature_of_hash: Vec<u8>,
}

impl AuthChallengeResponse {
    /// Verifies the challenge response. Returns the verified chain
    /// that signed the challenge bytes.
    pub fn verify(self, server_bytes: AuthChallenge) -> Result<SerializedChain, CertificateError> {
        let verified_chain = self.chain.clone().verify()?;

        let hash = server_bytes.hash(self.client_bytes);

        if verified_chain
            .verify_signature(&hash, &self.device_signature_of_hash)
            .is_ok()
        {
            Ok(self.chain)
        } else {
            Err(CertificateError::InvalidSignature)
        }
    }
}

impl From<AuthChallengeResponse> for proto::AuthenticationChallengePayload {
    fn from(value: AuthChallengeResponse) -> Self {
        Self {
            chain: Some(proto::CertificateChain::from(value.chain)),
            client_bytes: value.client_bytes.0.to_vec(),
            signature_of_hash: value.device_signature_of_hash,
        }
    }
}

impl TryFrom<proto::AuthenticationChallengePayload> for AuthChallengeResponse {
    type Error = ProtoError;

    fn try_from(value: proto::AuthenticationChallengePayload) -> Result<Self, Self::Error> {
        Ok(Self {
            chain: value
                .chain
                .ok_or(ProtoError)?
                .try_into()
                .map_err(|_| ProtoError)?,
            client_bytes: AuthChallenge(value.client_bytes.try_into().map_err(|_| ProtoError)?),
            device_signature_of_hash: value.signature_of_hash,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::certificates::tests::generate_fake_chain_secret;

    use super::*;

    #[test]
    fn test_challenge_ok() {
        let server_challenge = AuthChallenge::generate();

        let fake_chain = generate_fake_chain_secret();
        let client_accepts = server_challenge.accept(&fake_chain);

        let serialized = fake_chain.serialized();

        // Roundtrip to the server
        let serialized_response: proto::AuthenticationChallengePayload = client_accepts.into();
        let deserialized_response = AuthChallengeResponse::try_from(serialized_response)
            .expect("Roundtrip serialization works");

        let verified_chain = deserialized_response
            .verify(server_challenge)
            .expect("honest chain is valid");

        assert_eq!(verified_chain, serialized);
    }
}