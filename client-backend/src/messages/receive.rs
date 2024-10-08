use anyhow::Result;

/// Retrieve an `MlsMessageIn` (from a given person in a given group).
/// Verifies that the message is properly signed the sender's `Credential`,
/// then checks what the message is: is it encrypted text, plain text, a commit,
/// a proposal, a welcome etc. Then acts accordingly.
///
/// `sender_credential` _MUST_ BE OBTAINED FROM THE DB OR OTHER MEANS THAN THE MESSAGE CONTENTS ITSELF
/// (OTHERWISE THE SIGNING VERIFICATION PROCESS MEANS NOTHING)
///
/// If verification fails then the function returns an `Err`.
/// If you want to get an `MlsMessageIn` from bytes, use `MlsMessageIn::tls_deserialise`
pub fn process_incoming_message() -> Result<()> {
    todo!()
}
