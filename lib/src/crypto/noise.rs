#[derive(Default)]
#[allow(non_camel_case_types)]
enum SupportedHandshakes {
    #[default]
    // temporary until we move onto a KK scheme
    Noise_XX_25519_AESGCM_SHA256,
}

impl SupportedHandshakes {
    fn into_snow_params(self) -> snow::params::NoiseParams {
        match self {
            SupportedHandshakes::Noise_XX_25519_AESGCM_SHA256 => "Noise_XX_25519_AESGCM_SHA256"
                .parse()
                .expect("Correct handshake"),
        }
    }
}

/// A vector of bytes with a fixed maximum size of 65535.
#[derive(Debug, Clone)]
pub struct NoiseMessageBuffer {
    len: u16,
    buffer: Box<[u8; u16::MAX as usize]>,
}

impl Default for NoiseMessageBuffer {
    fn default() -> Self {
        Self {
            len: 0,
            // Does not initialize on stack on optimized builds.
            // Allocates 65.5kB on the heap
            buffer: Box::new([0; u16::MAX as usize]),
        }
    }
}

impl NoiseMessageBuffer {
    /// Writes `bytes` into the internal buffer.
    ///
    /// NOTE: Silently truncates `bytes` if the length of `bytes`
    /// is longer than 65535.
    #[inline(always)]
    pub fn write(&mut self, bytes: &[u8]) {
        let copy_length = std::cmp::min(bytes.len(), u16::MAX as usize);

        self.buffer[..copy_length].copy_from_slice(&bytes[..copy_length]);
        self.len = copy_length as u16;
    }

    /// Returns a mutable array of the internal buffer.
    ///
    /// This is used for `snow`, who checks the maximum message size
    /// internally. This does not update `len`.
    ///
    /// Prefer [`Self::write`] which checks buffer sizes.
    #[inline(always)]
    pub fn as_mut_unchecked(&mut self) -> &mut [u8] {
        self.buffer.as_mut_slice()
    }

    /// This is used for `snow`
    #[inline(always)]
    pub fn set_len_unchecked(&mut self, new_length: u16) {
        self.len = new_length;
    }

    #[inline(always)]
    pub fn read(&self) -> &[u8] {
        &self.buffer[..self.len as usize]
    }
}

impl AsRef<[u8]> for NoiseMessageBuffer {
    fn as_ref(&self) -> &[u8] {
        self.read()
    }
}

pub struct ClientHandshake {
    pub buffer: NoiseMessageBuffer,
    inner: snow::HandshakeState,
}

impl ClientHandshake {
    // TODO: Add client hash for auth challenge?
    pub fn prepare_handshake() -> Result<Self, snow::Error> {
        let builder = snow::Builder::new(SupportedHandshakes::default().into_snow_params());
        let keys = builder.generate_keypair()?;
        let builder = builder.local_private_key(&keys.private);

        let mut client = Self {
            buffer: NoiseMessageBuffer::default(),
            inner: builder.build_initiator()?,
        };

        let new_len = client
            .inner
            .write_message(&[], client.buffer.as_mut_unchecked())?;
        client.buffer.set_len_unchecked(new_len as u16);

        Ok(client)
    }

    pub fn complete_handshake(
        mut self,
        server_response: &[u8],
    ) -> Result<(NoiseTransport, NoiseMessageBuffer), snow::Error> {
        let new_len = self
            .inner
            .read_message(&server_response, self.buffer.as_mut_unchecked())?;
        self.buffer.set_len_unchecked(new_len as u16);

        let new_len = self
            .inner
            .write_message(&[], self.buffer.as_mut_unchecked())?;
        self.buffer.set_len_unchecked(new_len as u16);

        let handshake_response = self.buffer.clone();
        // "Empty" buffer to reuse it for Transport mode
        self.buffer.set_len_unchecked(0);

        Ok((
            NoiseTransport {
                buffer: self.buffer,
                inner: self.inner.into_transport_mode()?,
            },
            handshake_response,
        ))
    }
}

pub struct ServerHandshake {
    pub buffer: NoiseMessageBuffer,
    inner: snow::HandshakeState,
}

#[derive(Debug)]
pub struct NoiseTransport {
    buffer: NoiseMessageBuffer,
    inner: snow::TransportState,
}

impl ServerHandshake {
    pub fn respond(client_initiation: &[u8]) -> Result<Self, snow::Error> {
        let builder = snow::Builder::new(SupportedHandshakes::default().into_snow_params());
        let keys = builder.generate_keypair()?;
        let builder = builder.local_private_key(&keys.private);

        let mut server = Self {
            buffer: NoiseMessageBuffer::default(),
            inner: builder.build_responder()?,
        };

        let _new_len = server
            .inner
            .read_message(&client_initiation, server.buffer.as_mut_unchecked())?;
        // server.buffer.set_len_unchecked(new_len as u16);

        let new_len = server
            .inner
            .write_message(&[], server.buffer.as_mut_unchecked())?;
        server.buffer.set_len_unchecked(new_len as u16);

        Ok(server)
    }

    pub fn complete_handshake(
        mut self,
        client_response: &[u8],
    ) -> Result<NoiseTransport, snow::Error> {
        let _new_len = self
            .inner
            .read_message(&client_response, self.buffer.as_mut_unchecked())?;

        // "Empty" buffer to reuse it for Transport mode
        self.buffer.set_len_unchecked(0);

        Ok(NoiseTransport {
            buffer: self.buffer,
            inner: self.inner.into_transport_mode()?,
        })
    }
}

impl NoiseTransport {
    pub fn write(&mut self, bytes: &[u8]) -> Result<&[u8], snow::Error> {
        let new_len = self
            .inner
            .write_message(bytes, self.buffer.as_mut_unchecked())? as u16;
        self.buffer.set_len_unchecked(new_len);

        Ok(self.buffer.read())
    }

    pub fn read(&mut self, bytes: &[u8]) -> Result<&[u8], snow::Error> {
        let new_len = self
            .inner
            .read_message(bytes, self.buffer.as_mut_unchecked())? as u16;
        self.buffer.set_len_unchecked(new_len);

        Ok(self.buffer.read())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_handshake() {
        let client = ClientHandshake::prepare_handshake().expect("client handshake works");

        let server = ServerHandshake::respond(client.buffer.as_ref())
            .expect("server handshake response works");

        let (mut client_transport, client_response) = client
            .complete_handshake(server.buffer.as_ref())
            .expect("client completes handshake successfully");

        let mut server_transport = server
            .complete_handshake(client_response.as_ref())
            .expect("server completes handshake");

        assert!(client_transport.inner.is_initiator());

        assert!(!server_transport.inner.is_initiator());

        assert_eq!(
            client_transport.inner.sending_nonce(),
            server_transport.inner.receiving_nonce()
        );

        assert_eq!(
            server_transport.inner.sending_nonce(),
            client_transport.inner.receiving_nonce()
        );

        let wawa = b"wawa";
        let client_wawa = client_transport
            .write(wawa)
            .expect("client encryption works");
        let server_wawa = server_transport
            .read(client_wawa)
            .expect("server decryption works");

        assert_ne!(wawa, client_wawa);
        assert_eq!(wawa, server_wawa);

        let wewe = b"wewe";

        let server_wewe = server_transport
            .write(wewe)
            .expect("server encryption works");
        let client_wewe = client_transport
            .read(server_wewe)
            .expect("client decryption works");

        assert_ne!(wewe, server_wewe);
        assert_eq!(wewe, client_wewe);
    }
}
