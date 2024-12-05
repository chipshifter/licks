use crate::error::Error;
use lib::crypto::blinded_address::{BlindedAddressProof, BlindedAddressPublic};

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
    ba: BlindedAddressProof,
) -> Result<(BlindedAddressPublic, Vec<u8>), Error> {
    Ok(ba
        .verify()
        .map_err(lib::error::Error::BlindedAddressError)?)
}
