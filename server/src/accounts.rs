use std::sync::LazyLock;

use lib::{
    crypto::{
        certificates::{CertificateChain, SerializedChain},
        usernames::UsernameHash,
    },
    identifiers::{AccountId, LicksIdentifier},
};
use serde::{Deserialize, Serialize};
use sled::Tree;

use crate::{
    db::{deserialize_bytes, serialize_bytes, DB},
    error::Error,
};

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountInfo {
    username: UsernameHash,
    certificates: Vec<SerializedChain>,
}

/// A tree that keeps track of registered certificate chains for a given `AccountId`.
/// Key = `AccountId`,
/// Value = Vec<CredentialCertificate>
pub static REGISTERED_ACCOUNTS: LazyLock<Tree> =
    LazyLock::new(|| DB.open_tree("registered_account_ids").expect("tree opens"));

// What we want
// - Find all devices given an AccountId
// - Find an AccountId given a chain (it's stored in the chain so that's already done)
pub struct AccountService;

impl AccountService {
    pub fn is_account_registered(account_id: &AccountId) -> Result<bool, Error> {
        Ok(REGISTERED_ACCOUNTS.contains_key(account_id)?)
    }

    fn get_account_info(account_id: &AccountId) -> Result<Option<AccountInfo>, Error> {
        if let Some(account_info_bytes) = REGISTERED_ACCOUNTS.get(account_id)? {
            Ok(Some(deserialize_bytes::<AccountInfo, _>(
                &account_info_bytes,
            )?))
        } else {
            Ok(None)
        }
    }

    pub fn register_account(chain: SerializedChain, username: UsernameHash) -> Result<(), Error> {
        let account_id = *chain.account_id();

        let account_info = AccountInfo {
            username,
            certificates: vec![chain],
        };

        if !REGISTERED_ACCOUNTS.contains_key(account_id)? {
            let serialized_account_info = serialize_bytes(account_info)?;
            let _ = REGISTERED_ACCOUNTS.insert(account_id.to_bytes(), serialized_account_info)?;
        }

        Ok(())
    }

    /// Returns `true` if `chain` is one that is valid and registered to the server.
    /// This is `O(n)` with `n` the number of devices linked to the user.
    pub fn is_chain_valid(chain: &SerializedChain) -> Result<bool, Error> {
        let account_id = chain.account_id();
        if let Ok(Some(account_info)) = Self::get_account_info(account_id) {
            let db_chains = account_info.certificates;
            for db_chain in db_chains {
                if db_chain.eq(chain) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// This only works for registered accounts. If you want to register the certificate
    /// for a brand new account, then use [`Self::register_account`]
    pub fn add_new_device(_device_certificate_chain: &impl CertificateChain) -> Result<(), Error> {
        todo!("Only accept chains signed by another valid account chain")
    }
}
