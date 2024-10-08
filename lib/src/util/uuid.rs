/// High-level UUID generating function to unify
/// implementation between client and server seamlessly
///
/// This generateds a UUID V4, which is just made of
/// random bytes
#[inline]
pub fn generate_uuid() -> uuid::Uuid {
    uuid::Uuid::new_v4()
}
