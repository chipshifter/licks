//! MLS handles extensions in serialized forms (see [`super::Extension`] and [`super::Extensions`]).
//!
//! We therefore keep a separate enum of the non-serialized forms of every extension available, with
//! ways to convert between one another

use super::{Extension, ExtensionType, Extensions};
use crate::mls::utilities::error::Result;

#[derive(Debug, Clone)]
pub enum MlsExtension {
    ApplicationId(super::ApplicationIdExtension),
}

impl MlsExtension {
    #[allow(clippy::unnecessary_wraps)] // other things will return Result
    pub(crate) fn encode_extension(&self) -> Result<Extension> {
        match self {
            MlsExtension::ApplicationId(application_id_extension) => Ok(Extension {
                extension_type: ExtensionType::ApplicationId,
                extension_data: application_id_extension.0.clone(),
            }),
        }
    }

    pub(crate) fn decode_extension(extension: Extension) -> Result<Self> {
        match extension.extension_type {
            ExtensionType::ApplicationId => Ok(Self::ApplicationId(super::ApplicationIdExtension(
                extension.extension_data,
            ))),
            _ => todo!(),
        }
    }
}

impl TryFrom<Vec<MlsExtension>> for Extensions {
    type Error = crate::mls::utilities::error::Error;

    fn try_from(value: Vec<MlsExtension>) -> std::result::Result<Self, Self::Error> {
        let mut extensions = Vec::with_capacity(value.len());

        for mls_extension in value {
            extensions.push(mls_extension.encode_extension()?);
        }

        Ok(Self(extensions))
    }
}
