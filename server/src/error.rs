use lib::api::connection::ServiceError;
use sled::transaction::TransactionError;

use crate::{authenticator::AuthenticationError, services::register::RegistrationError};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("RegistrationError: {0}")]
    RegistrationError(#[from] RegistrationError),
    #[error("AuthenticationError: {0}")]
    AuthenticationError(#[from] AuthenticationError),
    #[error("LicksLibError: {0}")]
    LicksLibError(#[from] lib::error::Error),
    #[error("Sled database error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Sled database transaction error")]
    SledTransactionError,
    #[error("Bincode error: {0}")]
    BincodeError(#[from] bincode::Error),
    #[error("Axum error: {0}")]
    AxumError(#[from] axum::Error),
    #[error("Error processing request. Sending message back to client failed")]
    RequestError,
    #[error("Unknown error")]
    UnknownError,
}

impl From<TransactionError<()>> for Error {
    fn from(_value: TransactionError<()>) -> Self {
        Self::SledTransactionError
    }
}

impl From<Error> for ServiceError {
    fn from(value: Error) -> Self {
        tracing::error!("Internal server error while processing WS request: {value}");
        ServiceError::InternalError
    }
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        std::io::Error::new::<Error>(std::io::ErrorKind::Other, value)
    }
}

pub fn internal_err_ws(err: impl std::error::Error) -> ServiceError {
    tracing::error!("Internal error while processing WS request: {err}");

    ServiceError::InternalError
}
