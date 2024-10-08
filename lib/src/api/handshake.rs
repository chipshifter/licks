#[derive(Clone, Copy, Debug)]
enum HandshakeProgress {
    StartServer, // Recv E
    ServerSendES,
    ServerRecvS,
    StartClient, // Send E
    ClientRecvES,
    ClientSendS,
    Transport,
}

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

#[repr(u8)]
enum RpcCode {
    Ok = 0,
    Err = 1,
    Unknown,
}
impl RpcCode {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Ok,
            1 => Self::Err,
            _ => Self::Unknown,
        }
    }
}

impl HandshakeProgress {
    fn handshake(self) -> bool {
        !matches!(self, Self::Transport)
    }
    fn send(self) -> bool {
        match self {
            HandshakeProgress::StartServer
            | HandshakeProgress::ServerRecvS
            | HandshakeProgress::ClientRecvES => false,
            HandshakeProgress::ServerSendES
            | HandshakeProgress::StartClient
            | HandshakeProgress::ClientSendS
            | HandshakeProgress::Transport => true,
        }
    }
    fn recv(self) -> bool {
        match self {
            HandshakeProgress::StartServer
            | HandshakeProgress::ServerRecvS
            | HandshakeProgress::ClientRecvES
            | HandshakeProgress::Transport => true,
            HandshakeProgress::ServerSendES
            | HandshakeProgress::StartClient
            | HandshakeProgress::ClientSendS => false,
        }
    }
}

pub enum HandshakeResult {
    OkHandshake(Vec<u8>),
    OkTransport(Vec<u8>),
    Err(Vec<u8>),
    Closed,
}

impl HandshakeResult {
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Err(..) | Self::Closed)
    }
    pub fn is_err(&self) -> bool {
        matches!(self, HandshakeResult::Err(..))
    }
    pub fn to_bytes(self) -> Option<Vec<u8>> {
        match self {
            HandshakeResult::OkHandshake(vec)
            | HandshakeResult::OkTransport(vec)
            | HandshakeResult::Err(vec) => Some(vec),
            HandshakeResult::Closed => None,
        }
    }
}

// idealy we would want to use a coroutine in the future instead of an enum for state
pub struct NoiseState<S: HandshakeSupplier> {
    handshake_state: Option<Box<snow::HandshakeState>>,
    transport_state: Option<Box<snow::TransportState>>,
    channel_hash: Option<Vec<u8>>,
    buffer: Vec<u8>,
    #[allow(dead_code)]
    supplier: S,
    progress: HandshakeProgress,
}

pub enum StateType {
    Initiator,
    Responder,
}

/// This trait is a helper trait for the creation and destruction of man
pub trait HandshakeSupplier {
    type Error;
    fn new_handshake_state(
        &self,
        r#type: StateType,
    ) -> Result<Box<snow::HandshakeState>, Self::Error>
    where
        <Self as HandshakeSupplier>::Error: From<snow::Error>,
    {
        let builder = snow::Builder::new(SupportedHandshakes::default().into_snow_params());
        let keys = builder.generate_keypair()?;
        let builder = builder.local_private_key(&keys.private);
        match r#type {
            StateType::Initiator => Ok(Box::new(builder.build_initiator()?)),
            StateType::Responder => Ok(Box::new(builder.build_responder()?)),
        }
    }
}

impl<S: HandshakeSupplier> NoiseState<S> {
    pub fn new_client(supplier: S) -> Result<Self, S::Error>
    where
        <S as HandshakeSupplier>::Error: From<snow::Error>,
    {
        let b = vec![0; u16::MAX as usize];

        Ok(Self {
            handshake_state: Some(supplier.new_handshake_state(StateType::Initiator)?),
            transport_state: None,
            channel_hash: None,
            supplier,
            buffer: b,
            progress: HandshakeProgress::StartClient,
        })
    }

    pub fn new_server(supplier: S) -> Result<Self, S::Error>
    where
        <S as HandshakeSupplier>::Error: From<snow::Error>,
    {
        let b = vec![0; u16::MAX as usize];

        Ok(Self {
            handshake_state: Some(supplier.new_handshake_state(StateType::Responder)?),
            transport_state: None,
            channel_hash: None,
            supplier,
            buffer: b,
            progress: HandshakeProgress::StartServer,
        })
    }

    pub fn is_handshake(&self) -> bool {
        self.progress.handshake()
    }

    pub fn can_send(&self) -> bool {
        self.progress.send()
    }

    pub fn can_recv(&self) -> bool {
        self.progress.recv()
    }

    pub fn receive_bytes(&mut self, bytes: &mut [u8]) -> HandshakeResult {
        let progress = self.progress;

        let mut inner = |next: HandshakeProgress| {
            let mut v = Vec::new();
            let Some(hs) = self.handshake_state.as_mut().map(AsMut::as_mut) else {
                return HandshakeResult::Err(vec![1]);
            };

            match RpcCode::from_u8(bytes[0]) {
                RpcCode::Ok => {}
                RpcCode::Err => return HandshakeResult::Closed,
                RpcCode::Unknown => return HandshakeResult::Err(vec![1]),
            }

            let Ok(sz) = hs.read_message(&bytes[1..], &mut self.buffer) else {
                return HandshakeResult::Err(vec![1]);
            };

            v.reserve_exact(sz + 1);
            v.extend(self.buffer[..sz].iter());

            self.progress = next;

            HandshakeResult::OkHandshake(v)
        };

        match progress {
            HandshakeProgress::StartServer => inner(HandshakeProgress::ServerSendES),
            HandshakeProgress::ServerRecvS => {
                let f = inner(HandshakeProgress::Transport);
                if !f.is_terminal() {
                    let hs = self.handshake_state.take().unwrap();
                    self.channel_hash = Some(hs.get_handshake_hash().to_vec());
                    match hs.into_transport_mode() {
                        Ok(ts) => {
                            self.transport_state = Some(Box::new(ts));
                        }
                        Err(_e) => {
                            // TODO log error
                            return HandshakeResult::Err(vec![1]);
                        }
                    }
                }
                f
            }
            HandshakeProgress::ClientRecvES => inner(HandshakeProgress::ClientSendS),
            // Non-recv
            HandshakeProgress::StartClient
            | HandshakeProgress::ServerSendES
            | HandshakeProgress::ClientSendS => HandshakeResult::Err(vec![1]),
            HandshakeProgress::Transport => {
                const MAX_PER_DECRYPT_SIZE: usize = (u16::MAX - 16) as usize;
                match RpcCode::from_u8(bytes[0]) {
                    RpcCode::Ok => {}
                    RpcCode::Err => return HandshakeResult::Closed,
                    RpcCode::Unknown => return HandshakeResult::Err(vec![1]),
                }
                let mut fin = Vec::new();
                let Some(ts) = self.transport_state.as_mut() else {
                    return HandshakeResult::Err(vec![1]);
                };

                for chunk in bytes[1..].chunks(MAX_PER_DECRYPT_SIZE) {
                    let Ok(sz) = ts.read_message(chunk, &mut self.buffer) else {
                        return HandshakeResult::Err(vec![1]);
                    };
                    fin.extend_from_slice(&self.buffer[..sz]);
                }
                HandshakeResult::OkTransport(fin)
            }
        }
    }

    pub fn send_bytes(&mut self, bytes: &mut [u8]) -> HandshakeResult {
        let progress = self.progress;

        let mut inner = |next, bytes| {
            let mut v = Vec::new();
            let Some(hs) = self.handshake_state.as_mut().map(AsMut::as_mut) else {
                return HandshakeResult::Err(vec![1]);
            };
            let Ok(sz) = hs.write_message(bytes, &mut self.buffer) else {
                return HandshakeResult::Err(vec![1]);
            };

            v.reserve_exact(sz + 1);
            v.extend(self.buffer[..sz].iter());

            self.progress = next;

            HandshakeResult::OkHandshake(v)
        };

        match progress {
            HandshakeProgress::StartClient => inner(HandshakeProgress::ClientRecvES, &[]),
            HandshakeProgress::ServerSendES => inner(HandshakeProgress::ServerRecvS, &[]),
            HandshakeProgress::ClientSendS => inner(HandshakeProgress::Transport, &[]),
            // Non-send
            HandshakeProgress::StartServer
            | HandshakeProgress::ClientRecvES
            | HandshakeProgress::ServerRecvS => HandshakeResult::Err(vec![1]),
            HandshakeProgress::Transport => {
                const MAX_PER_DECRYPT_SIZE: usize = (u16::MAX - 16) as usize;
                match bytes[0] {
                    0 => {}
                    1 => return HandshakeResult::Closed,
                    _ => return HandshakeResult::Err(vec![1]),
                }
                let mut fin = Vec::new();
                let Some(ts) = self.transport_state.as_mut() else {
                    return HandshakeResult::Err(vec![1]);
                };

                for chunk in bytes[1..].chunks(MAX_PER_DECRYPT_SIZE) {
                    let Ok(sz) = ts.read_message(chunk, &mut self.buffer) else {
                        return HandshakeResult::Err(vec![1]);
                    };
                    fin.extend_from_slice(&self.buffer[..sz]);
                }
                HandshakeResult::OkTransport(fin)
            }
        }
    }
}
