use lib::{
    crypto::usernames::Username,
    identifiers::{AccountId, LicksIdentifier},
};
use rusqlite::params;

use super::{Database, DatabaseError};

impl Database {
    pub fn add_new_contact(
        &self,
        account_id: AccountId,
        username: Option<Username>,
        profile_name: Option<&str>,
        profile_description: Option<&str>,
    ) -> Result<(), DatabaseError> {
        // We ignore the unique constraint because when joining a group we may add the same account_id profile more
        // than once (if they have more than one device inside the group)
        self.get_connection().execute(
            r"
                INSERT OR IGNORE INTO contacts 
                    (account_id, username, profile_name, profile_description) 
                VALUES (?1, ?2, ?3, ?4)",
            params![
                account_id.as_uuid(),
                username.map(|ok| ok.0),
                profile_name,
                profile_description
            ],
        )?;

        Ok(())
    }
}
