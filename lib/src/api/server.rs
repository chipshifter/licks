use serde::{Deserialize, Serialize};

use crate::{
    constants::{DEFAULT_PORT_AUTHENTICATED, DEFAULT_PORT_UNAUTHENTICATED, LOCALHOST_DOMAIN},
    error::ProtoError,
};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Server {
    pub host: String,
    pub unauth_endpoint_port: u16,
    pub auth_endpoint_port: u16,
}

impl Server {
    pub fn localhost() -> Self {
        Self {
            host: LOCALHOST_DOMAIN.to_string(),
            unauth_endpoint_port: DEFAULT_PORT_UNAUTHENTICATED,
            auth_endpoint_port: DEFAULT_PORT_AUTHENTICATED,
        }
    }

    pub fn url_unauth(&self) -> String {
        format!("{}:{}", self.host, self.unauth_endpoint_port)
    }

    pub fn url_auth(&self) -> String {
        format!("{}:{}", self.host, self.auth_endpoint_port)
    }

    pub fn ws_url_unauth(&self) -> String {
        format!("ws://{}", self.url_unauth())
    }

    pub fn ws_url_auth(&self) -> String {
        format!("{}/auth", self.ws_url_unauth())
    }

    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.unauth_endpoint_port.to_be_bytes().to_vec();
        bytes.append(&mut self.auth_endpoint_port.to_be_bytes().to_vec());
        bytes.append(&mut self.host.as_bytes().to_vec());

        bytes
    }

    pub fn from_vec(vec: Vec<u8>) -> Result<Self, ProtoError>
    where
        Self: Sized,
    {
        const PORT_LENGTH: usize = size_of::<u16>();

        // This check prevents .split_off() from panicking.
        // The data must at least be long enough for two ports.
        if vec.len() <= 2 * PORT_LENGTH {
            return Err(ProtoError);
        }

        let mut port_bytes = vec;
        let mut port_auth_bytes = port_bytes.split_off(PORT_LENGTH);
        let domain_bytes = port_auth_bytes.split_off(PORT_LENGTH);

        let unauth_endpoint_port =
            u16::from_be_bytes(port_bytes.try_into().map_err(|_| ProtoError)?);

        let auth_endpoint_port =
            u16::from_be_bytes(port_auth_bytes.try_into().map_err(|_| ProtoError)?);

        let domain = String::from_utf8(domain_bytes).map_err(|_| ProtoError)?;

        Ok(Self {
            unauth_endpoint_port,
            auth_endpoint_port,
            host: domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_roundtrip() {
        let server = Server::localhost();
        let bytes = server.clone().to_vec();
        let roundtrip_server = Server::from_vec(bytes).expect("serialization roundtrip works");

        assert_eq!(
            server, roundtrip_server,
            "The server should be serialized and deserialized correctly after a roundtrip"
        );
    }
}
