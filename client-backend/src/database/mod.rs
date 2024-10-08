//! The module that handles the databases required by the client
//! whether that's `SQLite` or Sled/Ser-Sled.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use mls_rs_provider_sqlite::{connection_strategy::ConnectionStrategy, SqLiteDataStorageError};
use rusqlite::Connection;

pub mod contacts;
pub mod groups;
pub mod messages;
pub mod profile;
pub mod schemas;

#[derive(Debug, PartialEq, thiserror::Error)]
pub enum DatabaseError {
    #[error("This path is invalid")]
    InvalidPath,
    #[error("Error with the SQLCipher connection: {0}")]
    Rusqlite(#[from] rusqlite::Error),
    #[error("This data we attempted to retrieve is invalid/unexpected")]
    CorruptedData,
    #[error("This data is already present in the table")]
    AlreadyExists,
}

/// A `SQLCipher` connection
#[derive(Debug, Clone)]
pub struct Database {
    // If `None`, we open an in-memory database
    database_path: Option<PathBuf>,
    connection: Arc<Mutex<Connection>>,
}

impl ConnectionStrategy for Database {
    fn make_connection(&self) -> Result<Connection, SqLiteDataStorageError> {
        Self::open_connection(self.database_path.clone())
            .map_err(|e| SqLiteDataStorageError::SqlEngineError(e.into()))
    }
}

impl Database {
    /// Creates a Database object, opens a connection to the given path,
    /// and upgrades the database schema if needed.
    pub fn new(database_path: Option<PathBuf>) -> Result<Self, DatabaseError> {
        let mut conn = Self::open_connection(database_path.clone())?;

        Database::upgrade_database_version(&mut conn)?;

        Ok(Self {
            database_path,
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    /// A simple helper function to open a Databse in-memory.
    pub fn in_memory() -> Result<Self, DatabaseError> {
        Self::new(None)
    }

    /// Acquires the mutex  lock to the inner connection
    pub fn get_connection(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.connection.lock().expect("Mutex poisoning is safe")
    }

    /// Opens a new database connection.
    #[inline]
    fn open_connection(database_path: Option<PathBuf>) -> Result<Connection, DatabaseError> {
        if let Some(mut path) = database_path {
            path.push("db.sqlite");
            Ok(Connection::open(path)?)
        } else {
            Ok(Connection::open_in_memory()?)
        }
    }
}
