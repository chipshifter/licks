mod hash;
mod hpke;
mod signature;

use self::hash::HashSchemeWrapper;
use self::hpke::HpkeSuiteWrapper;
use self::signature::SignatureSchemeWrapper;
use super::{
    key_store::MemoryKeyStore, Aead, CipherSuite, CryptoProvider, Error, Hash, HashScheme, Hpke,
    HpkeSuite, Kdf, Kem, KeyStore, Result, Signature, SignatureScheme,
};

struct CipherSuiteDescription {
    hash: HashSchemeWrapper,
    hpke: HpkeSuiteWrapper,
    signature: SignatureSchemeWrapper,
}

static CIPHER_SUITE_DESCRIPTIONS: [CipherSuiteDescription; 1 /*CipherSuite::MLS_256_DHKEMP384_AES256GCM_SHA384_P384*/] = [
    //1: CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
    CipherSuiteDescription {
        hash: HashSchemeWrapper(HashScheme::SHA256),
        hpke: HpkeSuiteWrapper(HpkeSuite {
            kem: Kem::KEM_X25519_HKDF_SHA256,
            kdf: Kdf::KDF_HKDF_SHA256,
            aead: Aead::AEAD_AES128GCM,
        }),
        signature: SignatureSchemeWrapper(SignatureScheme::ED25519),
    },
];

/// [RustCrypto](https://github.com/RustCrypto) based crypto provider
#[derive(Default, Debug)]
pub struct RustCryptoProvider {
    key_store: MemoryKeyStore,
}

impl CryptoProvider for RustCryptoProvider {
    fn supports(&self, cipher_suite: CipherSuite) -> bool {
        matches!(
            cipher_suite,
            CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
        )
    }

    fn supported(&self) -> Vec<CipherSuite> {
        vec![CipherSuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519]
    }

    fn key_store(&self) -> &dyn KeyStore {
        &self.key_store
    }

    fn hash(&self, cipher_suite: CipherSuite) -> Result<&dyn Hash> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].hash)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }

    fn hpke(&self, cipher_suite: CipherSuite) -> Result<&dyn Hpke> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].hpke)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }

    fn signature(&self, cipher_suite: CipherSuite) -> Result<&dyn Signature> {
        if self.supports(cipher_suite) {
            let index: u16 = cipher_suite.into();
            Ok(&CIPHER_SUITE_DESCRIPTIONS[index as usize - 1].signature)
        } else {
            Err(Error::UnsupportedCipherSuite)
        }
    }
}
