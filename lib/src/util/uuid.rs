/// High-level UUID generating function to unify
/// implementation between client and server seamlessly
///
/// This generateds a UUID V4, which is just made of
/// random bytes
#[inline]
pub fn generate_uuid() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}

/// Generated a UUIDv7. This contains a timestamp
/// prefix of when the UUID was created (which in our case
/// is more efficient to store in databases and helps ensure
/// uniqueness) so it must not be used in cases where the UUID
/// is expected to not reveal any metadata.
#[inline]
pub fn generate_uuid_v7() -> uuid::Uuid {
    uuid::Uuid::now_v7()
}
