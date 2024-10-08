use crate::error::Error;
use lib::crypto::blinded_address::{BlindedAddressPublic, BlindedAddressSecret};

#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthenticationError {
    #[error("Authentication failed because we don't have the public key for that identifier.")]
    PublicKeyNotFound,
    #[error("Authentication failed because the ZK proof is invalid.")]
    InvalidZKProof,
    #[error("Authentication failed because the ZK proof couldn't be deserialised.")]
    ZKProofSerialisationError,
}

#[inline]
pub(crate) fn verify_blinded_address(
    ba: BlindedAddressSecret,
) -> Result<BlindedAddressPublic, Error> {
    Ok(ba
        .verify()
        .map_err(lib::error::Error::BlindedAddressError)?)
}
