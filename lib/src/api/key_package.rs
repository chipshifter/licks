//! The API structures used to communicate to the server.

use std::ops::Deref;

use mls_rs_core::key_package::KeyPackageData;
use serde::{Deserialize, Serialize};

/// A public API to key packages so that the server
/// can access it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyPackage {
    inner: KeyPackageData,
}

impl From<KeyPackageData> for KeyPackage {
    fn from(value: KeyPackageData) -> Self {
        Self { inner: value }
    }
}

impl Deref for KeyPackage {
    type Target = KeyPackageData;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
