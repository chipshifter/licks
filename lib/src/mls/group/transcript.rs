use bytes::Bytes;

use crate::mls::{
    crypto::provider::CryptoProvider,
    key_schedule::{ConfirmedTranscriptHashInput, InterimTranscriptHashInput},
    utilities::error::Result,
};

use super::Group;

/// As described in <https://www.rfc-editor.org/rfc/rfc9420.html#name-transcript-hashes>
///
/// "A `confirmed_transcript_hash` that represents a transcript over the whole history
/// of Commit messages, up to and including the signature of the most recent Commit."
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfirmedTranscriptHash {
    pub(crate) confirmed_hash: Bytes,
    pub(crate) interim_hash: Bytes,
}

impl Default for ConfirmedTranscriptHash {
    fn default() -> Self {
        // https://www.rfc-editor.org/rfc/rfc9420.html#section-8.2-7
        // ```
        // confirmed_transcript_hash_[0] = ""; /* zero-length octet string */
        // interim_transcript_hash_[0] = ""; /* zero-length octet string */
        // ```
        Self {
            confirmed_hash: Bytes::new(),
            interim_hash: Bytes::new(),
        }
    }
}

impl Group {
    /// Updates the confirmed transcript hash, and returns it.
    /// This does not modify the state of the group, nor does it increase the epoch.
    ///
    /// (?? This should be called after verifying [`AuthenticatedContent`]. ??)
    ///
    /// ```text
    /// confirmed_transcript_hash_[epoch] =
    ///     Hash(interim_transcript_hash_[epoch - 1] || ConfirmedTranscriptHashInput_[epoch]);
    /// interim_transcript_hash_[epoch] =
    ///     Hash(confirmed_transcript_hash_[epoch] || InterimTranscriptHashInput_[epoch]);
    /// ```
    pub(crate) fn hash_new_confirmed_transcript_hash(
        &self,
        crypto_provider: &impl CryptoProvider,
        new_confirmed_transcript: &ConfirmedTranscriptHashInput,
        new_interim_transcript: &InterimTranscriptHashInput,
    ) -> Result<ConfirmedTranscriptHash> {
        let cipher_suite = self.group_config.crypto_config.cipher_suite;
        let interim_transcript_hash_before = &self.confirmed_transcript_hash.interim_hash;

        let confirmed_transcript_hash_now = new_confirmed_transcript.hash(
            crypto_provider,
            cipher_suite,
            interim_transcript_hash_before,
        )?;

        let interim_transcript_hash_now = new_interim_transcript.hash(
            crypto_provider,
            cipher_suite,
            &confirmed_transcript_hash_now,
        )?;

        Ok(ConfirmedTranscriptHash {
            confirmed_hash: confirmed_transcript_hash_now,
            interim_hash: interim_transcript_hash_now,
        })
    }
}
