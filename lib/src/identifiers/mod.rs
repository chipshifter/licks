//! Structures for unique identifiers for Licks, based around UUIDs.
pub use uuid::Uuid;

pub mod account;
pub mod device;
pub mod group;

pub use {account::AccountId, device::DeviceId, group::GroupIdentifier};

#[derive(thiserror::Error, Debug)]
pub enum LicksIdentifierError {
    #[error("The input cannot be converted to a UUID")]
    InvalidInput,
}

pub const LICKS_IDENTIFIER_BYTES: usize = 16;

pub trait LicksIdentifier {
    fn generate_id() -> Self;
    fn as_uuid(&self) -> Uuid;
    fn to_bytes(&self) -> [u8; LICKS_IDENTIFIER_BYTES] {
        self.as_uuid().to_bytes_le()
    }
    /// Returns empty ID.
    fn none() -> Self;
}
pub trait IntoUuid {
    fn into_uuid(self) -> Uuid;
}

impl<T: LicksIdentifier> IntoUuid for &T {
    fn into_uuid(self) -> Uuid {
        self.as_uuid()
    }
}
