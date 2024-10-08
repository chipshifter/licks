use std::fmt::Display;

use base64ct::{Base64UrlUnpadded, Encoding};

#[derive(Debug, Clone)]
pub struct Base64String(String);

impl Display for Base64String {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Base64String {
    pub fn inner_str(&self) -> &str {
        &self.0
    }

    pub fn from_base64_str(s: &str) -> Option<Self> {
        Base64UrlUnpadded::decode_vec(s)
            .ok()
            .map(Base64String::from_bytes)
    }

    pub fn from_string_slice(s: &str) -> Self {
        dbg!(s);
        Self::from_bytes(s.as_bytes())
    }

    pub fn from_bytes<Bytes: AsRef<[u8]>>(bytes: Bytes) -> Self {
        Base64String(Base64UrlUnpadded::encode_string(bytes.as_ref()))
    }

    pub fn to_vec(&self) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(&self.0)
            .expect("Base64String type is guaranteed to be well formed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_base64_test() {
        let test = vec![1, 2, 3];
        assert_eq!(Base64String::from_bytes(&test).to_vec(), test);
    }

    #[test]
    fn simple_base64_string() {
        let test = "hello".to_string();
        let encoded = Base64String::from_string_slice(&test);
        assert_eq!(
            String::from_utf8(encoded.to_vec()).expect("valid utf-8"),
            test
        );
    }
}
