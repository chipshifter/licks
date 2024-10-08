use crate::mls::framing::{
    deserialize_opaque_vec, encrypt_sender_data, expand_sender_data_key, expand_sender_data_nonce,
    serialize_opaque_vec, AuthenticatedContent, Buf, BufMut, Bytes, CipherSuite, Commit, Content,
    ContentType, CryptoProvider, Deserializer, Error, FramedContent, FramedContentAuthData,
    GroupContext, MlsGroupId, Proposal, RatchetSecret, Result, Sender, SenderData, SenderDataAAD,
    Serializer, WireFormat,
};

/// [RFC9420 Sec.6.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3) Authenticated and
/// encrypted messages are encoded using the `PrivateMessage` structure.
///
/// 2024-09-27: Modified to remove the `group_id` and `epoch` field.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessage {
    pub content_type: ContentType,
    pub authenticated_data: Bytes,
    pub encrypted_sender_data: Bytes,
    pub ciphertext: Bytes,
}

impl Deserializer for PrivateMessage {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let content_type = ContentType::deserialize(buf)?;
        let authenticated_data = deserialize_opaque_vec(buf)?;
        let encrypted_sender_data = deserialize_opaque_vec(buf)?;
        let ciphertext = deserialize_opaque_vec(buf)?;

        Ok(Self {
            content_type,
            authenticated_data,
            encrypted_sender_data,
            ciphertext,
        })
    }
}

impl Serializer for PrivateMessage {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        self.content_type.serialize(buf)?;
        serialize_opaque_vec(&self.authenticated_data, buf)?;
        serialize_opaque_vec(&self.encrypted_sender_data, buf)?;
        serialize_opaque_vec(&self.ciphertext, buf)
    }
}

impl PrivateMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        crypto_provider: &impl CryptoProvider,
        cipher_suite: CipherSuite,
        sign_key: &[u8],
        secret: &RatchetSecret,
        sender_data_secret: &[u8],
        content: &FramedContent,
        sender_data: &SenderData,
        ctx: &GroupContext,
    ) -> Result<PrivateMessage> {
        let ciphertext = encrypt_private_message_content(
            crypto_provider,
            cipher_suite,
            sign_key,
            secret,
            content,
            ctx,
            &sender_data.reuse_guard,
        )?;
        let encrypted_sender_data = encrypt_sender_data(
            crypto_provider,
            cipher_suite,
            sender_data_secret,
            sender_data,
            content,
            &ciphertext,
        )?;

        Ok(PrivateMessage {
            content_type: content.content.content_type(),
            authenticated_data: content.authenticated_data.clone(),
            encrypted_sender_data,
            ciphertext,
        })
    }

    pub(crate) fn decrypt_sender_data(
        &self,
        crypto_provider: &impl CryptoProvider,
        group_context: &GroupContext,
        sender_data_secret: &[u8],
    ) -> Result<SenderData> {
        let cipher_suite = group_context.cipher_suite;
        let group_id = group_context.group_id.clone();
        let epoch = group_context.epoch;

        let key = expand_sender_data_key(
            crypto_provider,
            cipher_suite,
            sender_data_secret,
            &self.ciphertext,
        )?;
        let nonce = expand_sender_data_nonce(
            crypto_provider,
            cipher_suite,
            sender_data_secret,
            &self.ciphertext,
        )?;

        let aad = SenderDataAAD {
            group_id,
            epoch,
            content_type: self.content_type,
        };
        let raw_aad = aad.serialize_detached()?;

        let raw_sender_data = crypto_provider.hpke(cipher_suite)?.aead_open(
            &key,
            &nonce,
            &self.encrypted_sender_data,
            &raw_aad,
        )?;

        SenderData::deserialize_exact(&raw_sender_data)
    }

    pub(crate) fn decrypt_content(
        &self,
        crypto_provider: &impl CryptoProvider,
        group_context: &GroupContext,
        secret: &RatchetSecret,
        reuse_guard: &[u8],
    ) -> Result<PrivateMessageContent> {
        let cipher_suite = group_context.cipher_suite;
        let group_id = group_context.group_id.clone();
        let epoch = group_context.epoch;

        let (key, nonce) = derive_private_message_key_and_nonce(
            crypto_provider,
            cipher_suite,
            secret,
            reuse_guard,
        )?;

        let aad = PrivateContentAAD {
            group_id,
            epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
        };

        let raw_aad = aad.serialize_detached()?;
        let raw_content = crypto_provider.hpke(cipher_suite)?.aead_open(
            &key,
            &nonce,
            &self.ciphertext,
            &raw_aad,
        )?;

        let mut buf = raw_content.as_ref();
        PrivateMessageContent::deserialize(&mut buf, self.content_type)
    }

    pub(crate) fn authenticated_content(
        &self,
        group_context: &GroupContext,
        sender_data: &SenderData,
        content: &PrivateMessageContent,
    ) -> AuthenticatedContent {
        let group_id = group_context.group_id.clone();
        let epoch = group_context.epoch;

        AuthenticatedContent {
            wire_format: WireFormat::PrivateMessage,
            content: FramedContent {
                group_id,
                epoch,
                sender: Sender::Member(sender_data.leaf_index),
                authenticated_data: self.authenticated_data.clone(),
                content: content.content.clone(),
            },
            auth: content.auth.clone(),
        }
    }
}

/// [RFC9420 Sec.6.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1) Content to be
/// encrypted is encoded in a `PrivateMessageContent` structure.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateMessageContent {
    pub content: Content,
    pub auth: FramedContentAuthData,
}

impl PrivateMessageContent {
    fn deserialize<B>(buf: &mut B, ct: ContentType) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let content = match ct {
            ContentType::Application => Content::Application(deserialize_opaque_vec(buf)?),
            ContentType::Proposal => Content::Proposal(Proposal::deserialize(buf)?),
            ContentType::Commit => Content::Commit(Commit::deserialize(buf)?),
        };

        let auth = FramedContentAuthData::deserialize(buf, ct)?;

        while buf.has_remaining() {
            if buf.get_u8() != 0 {
                return Err(Error::PaddingContainsNonZeroBytes);
            }
        }

        Ok(Self { content, auth })
    }
}

impl Serializer for PrivateMessageContent {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        match &self.content {
            Content::Application(application) => serialize_opaque_vec(application, buf)?,
            Content::Proposal(proposal) => proposal.serialize(buf)?,
            Content::Commit(commit) => commit.serialize(buf)?,
        }

        self.auth.serialize(buf, self.content.content_type())
    }
}

/// [RFC9420 Sec.6.3.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-6.3.1) The Additional
/// Authenticated Data (AAD) input to the encryption contains an object of the following form,
/// with the values used to identify the key and nonce
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct PrivateContentAAD {
    pub group_id: MlsGroupId,
    pub epoch: u64,
    pub content_type: ContentType,
    pub authenticated_data: Bytes,
}

impl Deserializer for PrivateContentAAD {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let group_id = deserialize_opaque_vec(buf)?;
        if buf.remaining() < 8 {
            return Err(Error::BufferTooSmall);
        }
        let epoch = buf.get_u64();
        let content_type = ContentType::deserialize(buf)?;
        let authenticated_data = deserialize_opaque_vec(buf)?;

        Ok(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data,
        })
    }
}

impl Serializer for PrivateContentAAD {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_opaque_vec(&self.group_id, buf)?;
        buf.put_u64(self.epoch);
        self.content_type.serialize(buf)?;
        serialize_opaque_vec(&self.authenticated_data, buf)
    }
}

fn derive_private_message_key_and_nonce(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    secret: &RatchetSecret,
    reuse_guard: &[u8],
) -> Result<(Bytes, Bytes)> {
    let key = secret.derive_key(crypto_provider, cipher_suite)?;
    let mut nonce = secret.derive_nonce(crypto_provider, cipher_suite)?.to_vec();
    if nonce.len() < reuse_guard.len() {
        return Err(Error::NonceAndReuseGuardLenNotMatch);
    }

    for i in 0..reuse_guard.len() {
        nonce[i] ^= reuse_guard[i];
    }

    Ok((key, nonce.into()))
}

pub(crate) fn encrypt_private_message_content(
    crypto_provider: &impl CryptoProvider,
    cipher_suite: CipherSuite,
    sign_key: &[u8],
    secret: &RatchetSecret,
    content: &FramedContent,
    ctx: &GroupContext,
    reuse_guard: &[u8],
) -> Result<Bytes> {
    let auth_content = AuthenticatedContent::new(
        crypto_provider,
        cipher_suite,
        sign_key,
        WireFormat::PrivateMessage,
        content,
        ctx,
    )?;

    let priv_content = PrivateMessageContent {
        content: content.content.clone(),
        auth: auth_content.auth,
    };

    let plainttext = priv_content.serialize_detached()?;

    let (key, nonce) =
        derive_private_message_key_and_nonce(crypto_provider, cipher_suite, secret, reuse_guard)?;

    let aad = PrivateContentAAD {
        group_id: content.group_id.clone(),
        epoch: content.epoch,
        content_type: content.content.content_type(),
        authenticated_data: content.authenticated_data.clone(),
    };
    let raw_aad = aad.serialize_detached()?;

    crypto_provider
        .hpke(cipher_suite)?
        .aead_seal(&key, &nonce, &plainttext, &raw_aad)
}
