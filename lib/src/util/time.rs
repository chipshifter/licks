use std::array::TryFromSliceError;

use serde::{Deserialize, Serialize};

/// UUID v7/[`DeliveryId`] contains a big-endian, millisecond precise, UNIX timestamp.
/// This is the type that handles retrieving it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct UnixTimestamp([u8; 12]);

impl UnixTimestamp {
    pub const fn nil() -> Self {
        Self([0u8; 12])
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl From<uuid::Timestamp> for UnixTimestamp {
    fn from(value: uuid::Timestamp) -> Self {
        let (secs, millis) = value.to_unix();
        let mut bytes = [0u8; 12];

        // PANIC SAFETY: u64 is 8 bytes long.
        bytes[0..8].copy_from_slice(&secs.to_be_bytes());
        // PANIC SAFETY: u32 is 4 bytes long.
        bytes[8..12].copy_from_slice(&millis.to_be_bytes());

        Self(bytes)
    }
}

impl TryFrom<&[u8]> for UnixTimestamp {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(UnixTimestamp(value.try_into()?))
    }
}

impl TryFrom<uuid::Uuid> for UnixTimestamp {
    // Returns Err if the UUID does not have a timestamp (= isn't v1, v6, or v7)
    type Error = ();

    fn try_from(value: uuid::Uuid) -> Result<Self, Self::Error> {
        Ok(UnixTimestamp::from(value.get_timestamp().ok_or(())?))
    }
}

/// The timestamp at which the client generated the request. It is
/// different than [`ServerTimestamp`]. Consider this scenario: Alice
/// and Bob prepares two messages. Alice prepared her message faster than
/// Bob, so her [`ClientTimestamp`] is lower than Bob's. However, Bob has
/// a faster internet connection, so his message gets sent to the server
/// before Alice could. Therefore, Alice's [`ServerTimestamp`] is _higher_
/// than Bob's, not lower.
pub type ClientTimestamp = UnixTimestamp;

/// The timestamp at which the server received the request. It can be
/// seen as the "delivery" timestamp. When it comes to messages, this
/// timestamp is unique for messages in the a same group. This timestamp
/// is important to keep track of the ordering of group messages, and is
/// different than [`ClientTimestamp`]
pub type ServerTimestamp = UnixTimestamp;
