use std::fmt::Display;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
/// A hashed username.
///
/// This is what's stored in the server, to prevent the server
/// from knowing the plain-text username ([`UsernameString`]).
/// This is by no means perfect (the username space is short enough
/// that the hashes can be bruteforced with rainbow tables) but
/// it's better than nothing (and leaves room for future improvements)
///
/// Currently, we are using SHA256 as the crytographic hash.
pub struct UsernameHash(pub [u8; 32]);

impl From<[u8; 32]> for UsernameHash {
    fn from(value: [u8; 32]) -> Self {
        Self(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// A (valid) username.
///
/// Requirements for a valid username:
///  - Valid characters are: ., _, -, a-z, a-Z, 0-9
///  - Must be between 1 and 30 characters long
///
/// For privacy reasons, the server handles [`UsernameHash`] instead,
/// which you can obtain by simply calling [`UsernameString::hash`].
pub struct Username(pub String);

impl Display for Username {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsernameParseError {
    #[error("A username cannot be less than 1 character long")]
    TooShort,
    #[error("A username cannot be more than 30 characters long")]
    TooLong,
    #[error("A username cannot contain an invalid character. Valid characters are a-z, A-Z, 0-9, ., -, _")]
    InvalidCharacter,
}

impl AsRef<[u8]> for UsernameHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Username {
    /// Attempts to parse a [`String`] into a username.
    /// Returns a [`UsernameString`] if the String was valid, otherwise
    /// It will return [`UsernameError`].
    pub fn new(username: String) -> Result<Self, UsernameParseError> {
        if username.is_empty() {
            return Err(UsernameParseError::TooShort);
        }

        if username.len() > 30 {
            return Err(UsernameParseError::TooLong);
        }

        let iter = username.chars();

        for char in iter {
            match char {
                '.' | '_' | '-' | 'a'..='z' | 'A'..='Z' | '0'..='9' => {
                    // ok
                }
                _ => return Err(UsernameParseError::InvalidCharacter),
            };
        }

        // all checks passed, return ok
        Ok(Self(username))
    }

    pub fn hash(&self) -> UsernameHash {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let hash = hasher.finalize();

        UsernameHash(hash.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_username_hash() {
        let username = Username::new("wawa".to_string()).expect("username is valid");

        assert_eq!(
            username.hash().as_ref(),
            // Hash pre-calculated using a random web tool.
            // This is the SHA256 hash of b"wawa"
            hex_literal::hex!("8ad4264133a4549bee0972415277d6138d2cbab6dff3d4417c0b179d7e59a7a9")
        );
    }

    #[test]
    fn test_valid_username() {
        assert!(Username::new("john".to_string()).is_ok());
        assert!(Username::new("john123".to_string()).is_ok());
        assert!(Username::new("john.123".to_string()).is_ok());
        assert!(Username::new("john1-2-3".to_string()).is_ok());
        assert!(Username::new("jo.hn1_2-3".to_string()).is_ok());
        assert!(Username::new("k".to_string()).is_ok());
        assert!(Username::new("123456789012345678901234567890".to_string()).is_ok());

        // No weird characters
        assert_eq!(
            Username::new("john*".to_string()),
            Err(UsernameParseError::InvalidCharacter),
            "* is an invalid character"
        );
        assert_eq!(
            Username::new("john124&143".to_string()),
            Err(UsernameParseError::InvalidCharacter),
            "& is an invalid character"
        );

        // Can't be less than 1 character or more than 30
        assert_eq!(
            Username::new(String::new()),
            Err(UsernameParseError::TooShort),
            "username cannot be empty (length less than 1)"
        );
        assert_eq!(
            Username::new("1234567890123456789012345678901".to_string()),
            Err(UsernameParseError::TooLong),
            "username cannot be longer than 30 chars"
        );
    }
}
