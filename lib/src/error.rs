use std::sync::mpsc::TryRecvError;

use crate::crypto::blinded_address::BlindedAddressVerificationError;

#[derive(Debug, thiserror::Error, PartialEq)]
#[error("The protobuf could not be deserialized (invalid data or unexpected output).")]
pub struct ProtoError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Sender error: {0}")]
    Sender(#[from] TryRecvError),
    #[error("uuid error: {0}")]
    UuidError(#[from] uuid::Error),
    #[error("Manager is in the incorrect state")]
    IncorrectState,
    #[error("Blinded address error: {0}")]
    BlindedAddressError(#[from] BlindedAddressVerificationError),
    #[error("unknown error: `{0}` in file {1} on line {2}")]
    Unknown(&'static str, &'static str, u32),
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        std::io::Error::new::<Error>(std::io::ErrorKind::Other, value)
    }
}
