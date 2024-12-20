use std::sync::LazyLock;

use crate::db::DB;
use lib::{
    api::messages::{AuthRequest, Message, ServiceError, ServiceResult, UnauthRequest},
    crypto::usernames::UsernameHash,
    identifiers::{AccountId, LicksIdentifier},
};
use sled::Tree;

/// username hash -> [`AccountId`].
static USERNAME_TREE: LazyLock<Tree> = LazyLock::new(|| {
    DB.open_tree(b"usernames")
        .expect("we expect sled to be able to open trees")
});

pub struct UsernameService;

impl UsernameService {
    /// Retrieves the associated [`AccountId`]
    /// from a given username hash (32 bytes).
    pub fn find_account_id(username: UsernameHash) -> ServiceResult {
        if let Some(account_id_bytes) = USERNAME_TREE
            .get(username)
            .map_err(|_| ServiceError::InternalError)?
        {
            if let Ok(account_id) = AccountId::try_from(&*account_id_bytes) {
                Ok(Message::Unauth(UnauthRequest::HereIsAccount(account_id)))
            } else {
                Ok(Message::Unauth(UnauthRequest::NoAccount))
            }
        } else {
            Ok(Message::Unauth(UnauthRequest::NoAccount))
        }
    }

    pub fn set_username(verified_account_id: &AccountId, username: UsernameHash) -> ServiceResult {
        if let Some(user_in_db) = USERNAME_TREE
            .get(username)
            .map_err(|_| ServiceError::InternalError)?
        {
            if user_in_db == verified_account_id {
                // There's already a username, and it's ours
                Ok(Message::Auth(AuthRequest::UsernameIsAlreadyYours))
            } else {
                // There's already a username and it's not ours
                Ok(Message::Auth(AuthRequest::UsernameIsAlreadyTaken))
            }
        } else {
            // No one has that username, go with it
            let _ = USERNAME_TREE
                .insert(username, &verified_account_id.to_bytes())
                .map_err(|_| ServiceError::InternalError)?;
            Ok(Message::Ok)
        }
    }

    pub fn remove_username(
        verified_account_id: &AccountId,
        username: UsernameHash,
    ) -> ServiceResult {
        let Some(ivec) = USERNAME_TREE
            .get(username)
            .map_err(|_| ServiceError::InternalError)?
        else {
            return Err(ServiceError::InvalidRequest);
        };

        // Can't remove other people's usernames, can we
        if ivec.eq(&verified_account_id) {
            USERNAME_TREE
                .remove(username)
                .map_err(|_| ServiceError::InternalError)?;

            Ok(Message::Ok)
        } else {
            Err(ServiceError::InvalidCredentials)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib::crypto::usernames::Username;

    #[test]
    fn test_usernames() {
        let alice_username = Username::new("alice".to_string())
            .expect("username is valid")
            .hash();

        assert_eq!(
            UsernameService::find_account_id(alice_username),
            Ok(Message::Unauth(UnauthRequest::NoAccount,))
        );

        let alice_id = AccountId::generate_id();

        assert_eq!(
            UsernameService::set_username(&alice_id, alice_username),
            Ok(Message::Ok)
        );

        assert_eq!(
            UsernameService::find_account_id(alice_username),
            Ok(Message::Unauth(UnauthRequest::HereIsAccount(alice_id)))
        );

        let bob_id = AccountId::generate_id();
        let bob_username = Username::new("bob".to_string())
            .expect("username is valid")
            .hash();
        assert_eq!(
            UsernameService::remove_username(&bob_id, alice_username),
            Err(ServiceError::InvalidCredentials)
        );

        assert_eq!(
            UsernameService::set_username(&bob_id, alice_username),
            Ok(Message::Auth(AuthRequest::UsernameIsAlreadyTaken,))
        );

        assert_eq!(
            UsernameService::remove_username(&alice_id, alice_username),
            Ok(Message::Ok)
        );

        assert_eq!(
            UsernameService::find_account_id(alice_username),
            Ok(Message::Unauth(UnauthRequest::NoAccount,))
        );

        assert_eq!(
            UsernameService::set_username(&bob_id, bob_username),
            Ok(Message::Ok)
        );

        assert_eq!(
            UsernameService::set_username(&bob_id, bob_username),
            Ok(Message::Auth(AuthRequest::UsernameIsAlreadyYours,))
        );
    }
}
