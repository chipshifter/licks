use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{api::proto, error::ProtoError, util::uuid::generate_uuid};

use super::{LicksIdentifier, LicksIdentifierError};

#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Hash)]
pub struct DeviceId(Uuid);

impl AsRef<[u8]> for DeviceId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl TryFrom<&[u8]> for DeviceId {
    type Error = LicksIdentifierError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let uuid: Uuid = Uuid::from_slice(value).map_err(|_| LicksIdentifierError::InvalidInput)?;

        Ok(DeviceId::from(uuid))
    }
}

impl From<Uuid> for DeviceId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Device({})", self.0)
    }
}

impl LicksIdentifier for DeviceId {
    fn generate_id() -> Self {
        Self(generate_uuid())
    }

    fn as_uuid(&self) -> Uuid {
        self.0
    }

    fn to_bytes(&self) -> [u8; 16] {
        self.0.into_bytes()
    }

    fn none() -> Self {
        DeviceId(uuid::Uuid::nil())
    }
}

impl From<DeviceId> for proto::DeviceId {
    fn from(value: DeviceId) -> Self {
        Self {
            uuid: value.to_bytes().into(),
        }
    }
}

impl TryFrom<proto::DeviceId> for DeviceId {
    type Error = ProtoError;

    fn try_from(value: proto::DeviceId) -> Result<Self, Self::Error> {
        Ok(Self(Uuid::from_slice(&value.uuid).map_err(|_| ProtoError)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_UUID: &str = "8311e830-eeea-48ca-8fe3-5bcf09e11b57";

    #[test]
    fn create_display_device_identifier() {
        let uuid_str = Uuid::from_str(TEST_UUID).expect("valid uuid");
        let device_id = DeviceId::from(uuid_str);

        assert_eq!(
            "Device(8311e830-eeea-48ca-8fe3-5bcf09e11b57)",
            format!("{device_id}")
        );
    }
}
