//! MLS handles extensions in serialized forms (see [`super::Extension`] and [`super::Extensions`]).
//!
//! We therefore keep a separate enum of the non-serialized forms of every extension available, with
//! ways to convert between one another

use super::{Extension, ExtensionType, Extensions};
use crate::mls::{
    ratchet_tree::RatchetTree,
    utilities::{
        error::Result,
        serde::{Deserializer, Serializer},
    },
};

#[derive(Debug, Clone)]
pub enum MlsExtension {
    ApplicationId(super::ApplicationIdExtension),
    RatchetTree(super::RatchetTreeExtension),
}

impl MlsExtension {
    #[allow(clippy::unnecessary_wraps)] // other things will return Result
    pub(crate) fn encode_extension(&self) -> Result<Extension> {
        match self {
            MlsExtension::ApplicationId(application_id_extension) => Ok(Extension {
                extension_type: ExtensionType::ApplicationId,
                extension_data: application_id_extension.0.clone(),
            }),
            MlsExtension::RatchetTree(ratchet_tree_extension) => Ok(Extension {
                extension_type: ExtensionType::RatchetTree,
                extension_data: ratchet_tree_extension.ratchet_tree.serialize_detached()?,
            }),
        }
    }

    pub(crate) fn decode_extension(extension: Extension) -> Result<Self> {
        match extension.extension_type {
            ExtensionType::ApplicationId => Ok(Self::ApplicationId(super::ApplicationIdExtension(
                extension.extension_data,
            ))),
            ExtensionType::RatchetTree => Ok(Self::RatchetTree(super::RatchetTreeExtension {
                ratchet_tree: RatchetTree::deserialize_exact(extension.extension_data)?,
            })),
            _ => todo!(),
        }
    }
}

impl TryFrom<Vec<MlsExtension>> for Extensions {
    type Error = crate::mls::utilities::error::Error;

    fn try_from(value: Vec<MlsExtension>) -> std::result::Result<Self, Self::Error> {
        let extensions = value
            .into_iter()
            .filter_map(|mls_ext| mls_ext.encode_extension().ok())
            .collect();

        Ok(Self(extensions))
    }
}

impl TryFrom<Extensions> for Vec<MlsExtension> {
    type Error = crate::mls::utilities::error::Error;

    fn try_from(extensions: Extensions) -> std::result::Result<Self, Self::Error> {
        let mls_extensions = extensions
            .0
            .into_iter()
            .filter_map(|ext| MlsExtension::decode_extension(ext).ok())
            .collect();

        Ok(mls_extensions)
    }
}
