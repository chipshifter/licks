use crate::mls::{
    crypto::config::CryptoConfig,
    extensibility::{list::MlsExtension, Extensions},
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct GroupConfig {
    pub(crate) crypto_config: CryptoConfig,
    pub(crate) extensions: Extensions,
}

impl GroupConfig {
    /// Create a group config builder
    pub fn builder() -> GroupConfigBuilder {
        GroupConfigBuilder::new()
    }
}

#[derive(Default, Debug)]
pub struct GroupConfigBuilder {
    group_config: GroupConfig,
    extensions: Vec<MlsExtension>,
}

impl GroupConfigBuilder {
    /// Create a group config
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with crypto config
    #[must_use]
    pub fn with_crypto_config(mut self, crypto_config: CryptoConfig) -> Self {
        self.group_config.crypto_config = crypto_config;
        self
    }

    /// Build with extensions
    #[must_use]
    pub fn with_extensions(mut self, extensions: Vec<MlsExtension>) -> Self {
        self.extensions = extensions;
        self
    }

    /// Finalize and build the group config
    pub fn build(self) -> GroupConfig {
        self.group_config
    }
}
