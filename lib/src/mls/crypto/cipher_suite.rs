//! [RFC9420 Sec.5.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-5.1) Cipher Suite specifies
//! the cryptographic primitives to be used in group key computations.

use std::fmt::{Display, Formatter};

/// [RFC9420 Sec.17.1](https://www.rfc-editor.org/rfc/rfc9420.html#section-17.1) A cipher suite is a
/// combination of a protocol version and the set of cryptographic algorithms that should be used.
#[allow(non_camel_case_types)]
#[derive(Default, Debug, Copy, Clone, Eq, PartialEq, Hash)]
#[repr(u16)]
pub enum CipherSuite {
    #[default]
    MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 = 0x0001,
    Unknown(u16),
}

impl From<u16> for CipherSuite {
    fn from(v: u16) -> Self {
        match v {
            0x0001 => CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            _ => CipherSuite::Unknown(v),
        }
    }
}

impl From<CipherSuite> for u16 {
    fn from(val: CipherSuite) -> u16 {
        match val {
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 => 0x0001,
            CipherSuite::Unknown(v) => v,
        }
    }
}

impl Display for CipherSuite {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
