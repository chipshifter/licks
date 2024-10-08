use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use sled::Db;

use crate::error::Error;

pub static DB: LazyLock<Db> = LazyLock::new(|| {
    if cfg!(test) {
        let db_config = sled::Config::new().temporary(true);

        db_config
            .open()
            .expect("We have filesystem permissions to write to the given db path")
    } else {
        let db_config = sled::Config::new()
            .path("./data/server")
            .mode(sled::Mode::HighThroughput)
            // 2 GB CACHE = 2 000 000 000 BYTES
            .cache_capacity(1024 * 1024 * 1024 * 2);

        db_config
            .open()
            .expect("We have filesystem permissions to write to the given db path")
    }
});

pub fn serialize_bytes<T: Serialize>(stuff: T) -> Result<Vec<u8>, Error> {
    Ok(bincode::serialize(&stuff)?)
}

pub fn deserialize_bytes<T: for<'de> Deserialize<'de>, B: AsRef<[u8]>>(
    bytes: B,
) -> Result<T, Error> {
    Ok(bincode::deserialize(bytes.as_ref())?)
}
