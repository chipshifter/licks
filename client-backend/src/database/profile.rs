use rusqlite::params;

use crate::manager::account::Profile;

use super::{Database, DatabaseError};

impl Database {
    pub fn set_profile(&self, profile: &Profile) -> Result<(), DatabaseError> {
        self.get_connection().execute(
            r"
            INSERT INTO profile
                (data) 
            VALUES (?1)",
            params![profile.to_bytes()],
        )?;

        Ok(())
    }

    pub fn get_profile(&self) -> Result<Profile, DatabaseError> {
        let profile_bytes: Vec<u8> =
            self.get_connection()
                .query_row("SELECT data FROM profile", params![], |row| row.get(0))?;

        let profile =
            Profile::from_bytes(&profile_bytes).map_err(|_| DatabaseError::CorruptedData)?;

        Ok(profile)
    }
}
