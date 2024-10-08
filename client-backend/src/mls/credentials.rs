use lib::{
    crypto::certificates::{Certificate, CertificateChain, SerializedChain},
    error::ProtoError,
};
use mls_rs::{
    crypto::SignaturePublicKey,
    error::IntoAnyError,
    identity::{Credential, CredentialType, CustomCredential, SigningIdentity},
    time::MlsTime,
    ExtensionList, IdentityProvider,
};

pub const LICKS_CREDENTIAL_TYPE: CredentialType = CredentialType::new(0xfefe);

#[derive(PartialEq)]
pub struct LicksMlsCredential {
    pub(crate) chain: SerializedChain,
}

impl From<LicksMlsCredential> for SigningIdentity {
    fn from(value: LicksMlsCredential) -> Self {
        Self {
            signature_key: value.chain.pub_key_bytes().into(),
            credential: Credential::Custom(CustomCredential::from(value)),
        }
    }
}

impl TryFrom<SigningIdentity> for LicksMlsCredential {
    type Error = ProtoError;

    fn try_from(value: SigningIdentity) -> Result<Self, Self::Error> {
        let custom_cred = value.credential.as_custom().ok_or(ProtoError)?;

        let cred: LicksMlsCredential = custom_cred.try_into()?;

        if cred
            .chain
            .pub_key_bytes()
            .eq(value.signature_key.as_bytes())
        {
            Ok(cred)
        } else {
            Err(ProtoError)
        }
    }
}

impl From<LicksMlsCredential> for CustomCredential {
    fn from(value: LicksMlsCredential) -> Self {
        Self {
            credential_type: LICKS_CREDENTIAL_TYPE,
            data: value.chain.to_bytes(),
        }
    }
}

impl TryFrom<&CustomCredential> for LicksMlsCredential {
    type Error = ProtoError;

    fn try_from(value: &CustomCredential) -> Result<Self, Self::Error> {
        if value.credential_type == LICKS_CREDENTIAL_TYPE {
            let serialized_chain =
                SerializedChain::from_bytes(&value.data).map_err(|_| ProtoError)?;

            Ok(Self {
                chain: serialized_chain,
            })
        } else {
            Err(ProtoError)
        }
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LicksIdentityProvider;

impl LicksIdentityProvider {
    pub fn resolve_to_licks_credential(
        signing_identity: &SigningIdentity,
    ) -> Option<LicksMlsCredential> {
        match &signing_identity.credential {
            Credential::Custom(custom_cred) => custom_cred.try_into().ok(),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LicksIdentityProviderError {
    #[error("The credential could not be deserialized or is not supported")]
    Unsupported,
    #[error("The signer is invalid: the certificate chain is invalid")]
    InvalidCertificate,
    #[error("The signer is invalid: the public key is not the one stored in the chain")]
    InvalidPublicKey,
}

impl IntoAnyError for LicksIdentityProviderError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Err(self)
    }
}

impl IdentityProvider for LicksIdentityProvider {
    /// Error type that this provider returns on internal failure.
    type Error = LicksIdentityProviderError; // todo : make it not be ()

    /// Determine if `signing_identity` is valid for a group member.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](mls-rs-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // IMPORTANT TODO:
        // - Validate that AccountCredential is correct by contacting the authentication service
        // at the domain that is stored inside the credential

        let cred = Self::resolve_to_licks_credential(signing_identity)
            .ok_or(LicksIdentityProviderError::Unsupported)?;

        let chain = cred
            .chain
            .verify()
            .map_err(|_| LicksIdentityProviderError::InvalidCertificate)?;

        let pub_key = SignaturePublicKey::new(chain.device_cert().pub_key_bytes());
        if pub_key == signing_identity.signature_key {
            Ok(())
        } else {
            Err(LicksIdentityProviderError::InvalidPublicKey)
        }
    }

    /// Determine if `signing_identity` is valid for an external sender in
    /// the `ExternalSendersExtension` stored in the group context.
    ///
    /// A `timestamp` value can optionally be supplied to aid with validation
    /// of a [`Credential`](mls-rs-core::identity::Credential) that requires
    /// time based context. For example, X.509 certificates can become expired.
    fn validate_external_sender(
        &self,
        signing_identity: &SigningIdentity,
        timestamp: Option<MlsTime>,
        extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // IMPORTANT TODO:
        // - Should we really perform the same checks as validate_member?
        // - Validate that AccountCredential is correct by contacting the authentication service
        // at the domain that is stored inside the credential
        self.validate_member(signing_identity, timestamp, extensions)
    }

    /// A unique identifier for `signing_identity`.
    ///
    /// The MLS protocol requires that each member of a group has a unique
    /// set of identifiers according to the application.
    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let chain = Self::resolve_to_licks_credential(signing_identity)
            .ok_or(LicksIdentityProviderError::Unsupported)?
            .chain;

        Ok(chain.to_bytes())
    }

    /// Determines if `successor` can remove `predecessor` as part of an external commit.
    ///
    /// The MLS protocol allows for removal of an existing member when adding a
    /// new member via external commit. This function determines if a removal
    /// should be allowed by providing the target member to be removed as
    /// `predecessor` and the new member as `successor`.
    fn valid_successor(
        &self,
        _predecessor: &SigningIdentity,
        _successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        // In the future we'll have admin permissions etc
        // so that people can remove others from groups.
        // For now we'll just ignore that problem and pretend
        // anyone can kick anyone else from the group.
        Ok(true)
    }

    /// Credential types that are supported by this provider.
    fn supported_types(&self) -> Vec<CredentialType> {
        vec![LICKS_CREDENTIAL_TYPE]
    }
}
