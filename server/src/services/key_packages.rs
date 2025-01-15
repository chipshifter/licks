use lib::{
    api::messages::{AuthRequest, Message, ServiceResult, UnauthRequest},
    identifiers::{AccountId, LicksIdentifier},
};
use serde::{Deserialize, Serialize};
use sled::{transaction::abort, Tree};

use crate::{
    db::{deserialize_bytes, serialize_bytes, DB},
    error::{internal_err_ws, Error},
};

#[derive(Serialize, Deserialize)]
struct KeyPackageTreeInfo {
    pub count: u16,
}
/// A zero byte array, used as the key for the bloom filter+counter.
const INFO_KEY: [u8; 8] = 0u64.to_be_bytes();

pub struct KeyPackageService;

impl KeyPackageService {
    fn open_user_tree(account_id: &AccountId) -> Result<Tree, Error> {
        // "keypackages/" (12 bytes) + AccountId (which is a Uuid so 16 bytes) = 28 bytes
        let mut bytes: [u8; 28] = [0u8; 28];
        bytes[..12].copy_from_slice(b"keypackages/");
        bytes[12..].copy_from_slice(account_id.as_uuid().as_bytes());

        Ok(DB.open_tree(bytes)?)
    }

    pub fn upload_key_package(
        verified_account_id: &AccountId,
        key_packages: &[Vec<u8>],
    ) -> ServiceResult {
        tracing::info!(
            "Uploading {:?} key packages to user {:?}",
            key_packages.len(),
            verified_account_id
        );

        let user_keypackages_tree =
            Self::open_user_tree(verified_account_id).map_err(internal_err_ws)?;

        if !user_keypackages_tree.is_empty() {
            let tx_result = user_keypackages_tree.transaction(|tx| {
                // Update bloom filter and counter
                let Some(info) = tx.get(INFO_KEY)?.map(|ivec| ivec.to_vec()) else {
                    return abort(());
                };

                let Some(mut info): Option<KeyPackageTreeInfo> = deserialize_bytes(info).ok()
                else {
                    return abort(());
                };

                let mut added: u16 = 0;

                for key_package in key_packages {
                    if let Some(new_count) = info.count.checked_add(1) {
                        info.count = new_count;
                    } else {
                        // overflow, too many key packages already uploaded,
                        // stop inserting here
                        break;
                    }
                    added += 1;
                    tx.insert(&info.count.to_be_bytes(), key_package.as_slice())?;
                }

                let Some(info): Option<Vec<u8>> = serialize_bytes(info).ok() else {
                    return abort(());
                };

                tx.insert(&INFO_KEY, info)?;

                Ok(added)
            });

            match tx_result {
                Ok(0) => return Ok(Message::Auth(AuthRequest::KeyPackageAlreadyUploaded)),
                Ok(_) => return Ok(Message::Ok),
                Err(_) => {
                    tracing::warn!("Transaction failed while adding key package--Clearing tree and will try to initialize it");
                    user_keypackages_tree.clear().map_err(Error::from)?;
                }
            };
        }

        // If we land here then the tree is either corrupted
        // or we need to initiate it because it's empty
        let added = user_keypackages_tree
            .transaction(|tx| {
                let mut added: u16 = 0;
                for key_package in key_packages {
                    if let Some(new_count) = added.checked_add(1) {
                        added = new_count;
                        tx.insert(&new_count.to_be_bytes(), key_package.as_slice())?;
                    }
                }

                let Ok(info_bytes) = serialize_bytes(KeyPackageTreeInfo { count: added }) else {
                    return abort(());
                };

                tx.insert(&INFO_KEY, info_bytes.as_slice())?;

                Ok(added)
            })
            .map_err(Error::from)?;

        if added > 0 {
            Ok(Message::Ok)
        } else {
            Ok(Message::Auth(AuthRequest::KeyPackageAlreadyUploaded))
        }
    }

    pub fn get_key_package(account_id: AccountId) -> ServiceResult {
        let user_keypackages_tree = Self::open_user_tree(&account_id).map_err(internal_err_ws)?;

        let key_package: Option<Vec<u8>> = user_keypackages_tree
            .transaction(|tx| match tx.get(INFO_KEY)? {
                Some(info_bytes) => {
                    let Some(mut info): Option<KeyPackageTreeInfo> =
                        deserialize_bytes(info_bytes).ok()
                    else {
                        return abort(());
                    };

                    if info.count > 1 {
                        let key_package = tx
                            .remove(&info.count.to_be_bytes())?
                            .map(|ivec| ivec.to_vec());

                        // Decrease counter, update tree
                        info.count -= 1;
                        let Some(info_bytes): Option<Vec<u8>> = serialize_bytes(info).ok() else {
                            return abort(());
                        };
                        tx.insert(&INFO_KEY, info_bytes)?;

                        Ok(key_package)
                    } else {
                        Ok(tx.get(info.count.to_be_bytes())?.map(|ivec| ivec.to_vec()))
                    }
                }
                None => Ok(None),
            })
            .map_err(Error::from)?;

        match key_package {
            Some(kp) => Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(kp))),
            None => Ok(Message::Unauth(UnauthRequest::NoKeyPackage)),
        }
    }
}

#[cfg(test)]
mod tests {
    use lib::util::uuid::generate_uuid;

    use super::*;

    #[test]
    fn key_package_upload_and_get() {
        let account_id = AccountId::generate_id();

        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::NoKeyPackage))
        );

        // Generate one fake key package
        let key_package = generate_uuid().as_bytes().to_vec();
        let key_package_vec = vec![key_package.clone()];

        assert_eq!(
            KeyPackageService::upload_key_package(&account_id, &key_package_vec),
            Ok(Message::Ok)
        );

        // Because this is a "last resort" we can retrieve it as many times as we want
        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                key_package.clone()
            )))
        );
        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                key_package.clone()
            )))
        );

        // Let's upload another one
        let other_key_package = generate_uuid().as_bytes().to_vec();

        assert_eq!(
            KeyPackageService::upload_key_package(&account_id, &[other_key_package.clone()]),
            Ok(Message::Ok)
        );

        // Retrieving that new one pops it from the database, and keeps the other one still as a resort
        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                other_key_package
            )))
        );
        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                key_package
            )))
        );
    }

    #[test]
    fn key_package_upload_too_many() {
        let account_id = AccountId::generate_id();

        // We generate and upload 256 key packages.
        // This will be one too much and the server won't upload that last one.
        let count = 256;
        let mut key_packages = Vec::with_capacity(count);
        for _ in 0..count {
            key_packages.push(generate_uuid().as_bytes().to_vec());
        }

        // Upload
        KeyPackageService::upload_key_package(&account_id, &key_packages)
            .expect("Upload works fine still");

        for i in (0..255).rev() {
            assert_eq!(
                KeyPackageService::get_key_package(account_id),
                Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                    key_packages.get(i).expect("i is less than count").clone()
                )))
            );
        }

        // last resort still stands
        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                key_packages
                    .first()
                    .expect("count is more than zero")
                    .clone()
            )))
        );

        assert_eq!(
            KeyPackageService::get_key_package(account_id),
            Ok(Message::Unauth(UnauthRequest::HereIsKeyPackage(
                key_packages
                    .first()
                    .expect("count is more than zero")
                    .clone()
            )))
        );
    }
}
