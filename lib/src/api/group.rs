use crate::{
    crypto::blinded_address::{BlindedAddressProof, BlindedAddressPublic},
    util::uuid::generate_uuid_v7,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A stamp uniquely identifying messages and their relevant
/// timetamps. It is actually a Uuid v7, which
/// is a Uuid containing a unix millisecond timestamp + some
/// randomness.
///
/// It's used three times. Take Alice sending a message to Bob:
/// - Alice generates a Stamp, encrypts her message, and
///   sends it to the server (used in her local database and to
///   let others know when the message was made).
/// - The server receives the message, generates a stamp for it
///   and saves it into its database (used to generate a unique
///   UUID per message per group and sync that between clients).
/// - When Bob comes retrieve the message, he also generates a
///   stamp for himself (used in his local database)
///
/// The client generates one when sending (so other clients know
/// when the message was created), and the server generates one
/// when receiving the message (so all clients know when the message
/// was delivered).
///
/// The server also stores messages using the `DeliveryId` as the key,
/// and two messages A and B are such that B's delivery ID is greater than A's,
/// then B was delivered/received by the server *after* A.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct DeliveryStamp(Uuid);

impl DeliveryStamp {
    pub fn generate() -> Self {
        DeliveryStamp(generate_uuid_v7())
    }

    /// Returns the embedded timestamp.
    pub fn uuid_timestamp(&self) -> uuid::Timestamp {
        self.0
            .get_timestamp()
            .expect("DeliveryStamp is guaranteed to contain a timestamp")
    }

    /// Returns the representing bytes. Note that UUID V7
    /// stores the timestamp as a big-endian, so this output
    /// can be considered to be big-endian.
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.0.into()
    }
}

// This doesn't guarantee the timestamp will be correct though,
// which I'm slightly concerned about
impl TryFrom<&[u8]> for DeliveryStamp {
    type Error = ();

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(Uuid::from_slice(value).map_err(|_| ())?))
    }
}

impl TryFrom<uuid::Uuid> for DeliveryStamp {
    // Returns Err if the UUID does not have a timestamp (= isn't v1, v6, or v7)
    type Error = ();

    fn try_from(value: uuid::Uuid) -> Result<Self, Self::Error> {
        if value.get_timestamp().is_some() {
            Ok(DeliveryStamp(value))
        } else {
            Err(())
        }
    }
}

// Hopefully will work for both users and groups
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SendMessageRequest {
    pub blinded_address_proof: BlindedAddressProof,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct GetMessagesRequest {
    pub blinded_address: BlindedAddressPublic,
    pub server_delivery_id: DeliveryStamp,
}
