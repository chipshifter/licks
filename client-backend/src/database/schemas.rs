//! Schemas used to create the database
//! For backwards compatibility in the future we will keep all the schemas,
//! even the ones we end up reverting.
//!
//! (dev) For now since we just keep things in-memory we won't do that
//!
//! We use an iterator to skip the migration schemas if necessary.
//! The `SQLite` database will keep a version number internally.
use rusqlite::{params, Connection};

use super::{Database, DatabaseError};

/// The latest version of the database. It's just an
/// integer increasing by one every time we add
/// a new schema.
pub const LATEST_DATABASE_VERSION: usize = 2;

pub const SCHEMAS: [&str; LATEST_DATABASE_VERSION] = [
    "
    CREATE TABLE info(
        database_version            INTEGER     NOT NULL
    );

    CREATE TABLE contacts(
        account_id                  BLOB        PRIMARY KEY,
        username                    TEXT,
        profile_name                TEXT,
        profile_description         TEXT
    );

    CREATE TABLE messages(
        id                          INTEGER     PRIMARY KEY,
        group_id                    BLOB        NOT NULL,
        account_id                  BLOB        NOT NULL,
        server_timestamp            INTEGER     NOT NULL,
        received_timestamp          INTEGER     NOT NULL,
        message_kind                INTEGER     NOT NULL,
        plaintext_content           TEXT,
        reply_message_timestamp     INTEGER,
        FOREIGN KEY(group_id)   REFERENCES mls_group(group_id)
        FOREIGN KEY(account_id) REFERENCES contacts(account_id)
    );

    CREATE TABLE profile(
        data                        BLOB        PRIMARY KEY
    );

    CREATE TABLE group_info(
        group_id                    BLOB,
        epoch_id                    INTEGER,
        group_name                  TEXT        NOT NULL,
        group_description           TEXT,
        blinded_address             BLOB        NOT NULL,
        PRIMARY KEY (group_id, epoch_id)
    );
    ",
    // Tables used by mls-rs as of 0.41.0
    // Code taken from [`SqLiteDataStorageEngine::create_tables_v1`] in mls-rs-provider-sqlite
    // https://github.com/awslabs/mls-rs/blob/0.41.0/mls-rs-provider-sqlite/src/lib.rs#L118
    "
    CREATE TABLE mls_group (
        group_id BLOB PRIMARY KEY,
        snapshot BLOB NOT NULL
    ) WITHOUT ROWID;
    
    CREATE TABLE epoch (
        group_id BLOB,
        epoch_id INTEGER,
        epoch_data BLOB NOT NULL,
        FOREIGN KEY (group_id) REFERENCES mls_group (group_id) ON DELETE CASCADE
        PRIMARY KEY (group_id, epoch_id)
    ) WITHOUT ROWID;
    
    CREATE TABLE key_package (
        id BLOB PRIMARY KEY,
        expiration INTEGER,
        data BLOB NOT NULL
    ) WITHOUT ROWID;
    
    CREATE INDEX key_package_exp ON key_package (expiration);
    
    CREATE TABLE psk (
        psk_id BLOB PRIMARY KEY,
        data BLOB NOT NULL
    ) WITHOUT ROWID;
    
    CREATE TABLE kvs (
        key TEXT PRIMARY KEY,
        value BLOB NOT NULL
    ) WITHOUT ROWID;
    PRAGMA user_version = 1;
    ",
];

/// If needed, execute the new schemas to upgrade
/// the database to the latest version
impl Database {
    pub fn upgrade_database_version(conn: &mut Connection) -> Result<(), DatabaseError> {
        // Read current database version.
        // If we can't read it somehow, we assume that
        // the database is empty and so return a version of 0.
        let current_database_version: usize = conn
            .query_row("SELECT database_version FROM info", (), |row| {
                Ok(row.get(0).unwrap_or(0))
            })
            .unwrap_or(0);

        let transaction = conn.transaction()?;

        SCHEMAS
            .iter()
            .skip(current_database_version)
            .for_each(|query| {
                // We assume that the database migration queries are valid.
                // In the event of a failure we prefer to panic.
                transaction
                    .execute_batch(query)
                    .expect("Valid migration queries");
            });

        // Migration done, now we update database version
        if current_database_version > 0 {
            transaction.execute(
                "UPDATE info SET database_version = ?1",
                params![LATEST_DATABASE_VERSION],
            )?;
        } else {
            // The version hasn't been inserted yet
            transaction.execute(
                "INSERT INTO info (database_version) VALUES (?1)",
                [LATEST_DATABASE_VERSION],
            )?;
        }

        transaction.commit()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_automatic_upgrade() {
        let db = Database::in_memory().expect("db starts and upgrades automatically");

        let version: usize = db
            .get_connection()
            .query_row("SELECT database_version FROM info", (), |row| {
                Ok(row.get(0).unwrap_or(0))
            })
            .unwrap_or(0);

        assert_eq!(version, LATEST_DATABASE_VERSION);
    }

    #[test]
    fn test_upgrade() {
        // Manually open connection to prevent automatically upgrading
        let mut conn = Database::open_connection(None).expect("Connection opens");

        {
            let version: usize = conn
                .query_row("SELECT database_version FROM info", (), |row| {
                    Ok(row.get(0).unwrap_or(0))
                })
                .unwrap_or(0);

            assert_eq!(version, 0);
        };

        Database::upgrade_database_version(&mut conn).expect("upgrade works correctly");

        {
            let version: usize = conn
                .query_row("SELECT database_version FROM info", (), |row| {
                    Ok(row.get(0).unwrap_or(0))
                })
                .unwrap_or(0);

            assert_eq!(version, LATEST_DATABASE_VERSION);
        };
    }
}
