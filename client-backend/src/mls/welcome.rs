use lib::util::base64::Base64String;
use mls_rs::MlsMessage;

/// Returns None if [`MlsMessage`] is not a Welcome message.
///
/// TODO: Remove this with a better mechanism
pub fn welcome_to_base64(welcome_message: &MlsMessage) -> Option<Base64String> {
    if let Ok(bytes) = welcome_message.to_bytes() {
        Some(Base64String::from_bytes(bytes))
    } else {
        None
    }
}

pub fn base64_string_to_welcome(s: &str) -> Option<MlsMessage> {
    // At that point, we don't know whether the String we have
    // is a valid base64 string. We do the stupid thing of converting that
    // String to bytes, and then those bytes to a Base64 String, which
    // guarantees to give a valid Base64 String. Worst case, we converted
    // a valid base64 string for no reason.
    Base64String::from_base64_str(s).and_then(|ok| MlsMessage::from_bytes(&ok.to_vec()).ok())
}
