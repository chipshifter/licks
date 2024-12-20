use crate::{api::proto, error::ProtoError, util::uuid::generate_uuid};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{LicksIdentifier, LicksIdentifierError};

/// `GroupIdentifier` is the unique identifier used to handle groups.
///
/// This identifiers are generated during group creation and never changes.
///
/// It contains utility functions for easily retrieving a group or information
/// about it.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Serialize, Deserialize, Hash, PartialOrd, Ord)]
pub struct GroupIdentifier(Uuid);

impl GroupIdentifier {
    /// The [`GroupIdentifier`] of the "Personal notes" group
    pub fn self_id() -> Self {
        GroupIdentifier(uuid::Uuid::max())
    }
}

impl AsRef<[u8]> for GroupIdentifier {
    fn as_ref(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<Uuid> for GroupIdentifier {
    fn from(value: Uuid) -> Self {
        GroupIdentifier(value)
    }
}

impl TryFrom<&[u8]> for GroupIdentifier {
    type Error = LicksIdentifierError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let uuid: Uuid = Uuid::from_slice(value).map_err(|_| LicksIdentifierError::InvalidInput)?;

        Ok(GroupIdentifier::from(uuid))
    }
}

impl From<GroupIdentifier> for proto::GroupId {
    fn from(value: GroupIdentifier) -> Self {
        Self {
            uuid: value.to_bytes().into(),
        }
    }
}

impl TryFrom<proto::GroupId> for GroupIdentifier {
    type Error = ProtoError;

    fn try_from(value: proto::GroupId) -> Result<Self, Self::Error> {
        Ok(Self(Uuid::from_slice(&value.uuid).map_err(|_| ProtoError)?))
    }
}

impl std::fmt::Display for GroupIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Group({})", self.0)
    }
}

impl LicksIdentifier for GroupIdentifier {
    fn generate_id() -> Self {
        GroupIdentifier(generate_uuid())
    }

    fn as_uuid(&self) -> Uuid {
        self.0
    }

    fn to_bytes(&self) -> [u8; 16] {
        self.0.into_bytes()
    }

    fn none() -> Self {
        GroupIdentifier(uuid::Uuid::nil())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    const TEST_UUID: &str = "8311e830-eeea-48ca-8fe3-5bcf09e11b57";

    #[test]
    fn create_display_group_identifier() {
        let uuid_str = Uuid::from_str(TEST_UUID).expect("valid uuid");
        let group_id = GroupIdentifier::from(uuid_str);

        assert_eq!(
            "Group(8311e830-eeea-48ca-8fe3-5bcf09e11b57)",
            format!("{group_id}")
        );
    }
}
