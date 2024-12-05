use lib::{
    crypto::blinded_address::BlindedAddressSecret,
    identifiers::{GroupIdentifier, LicksIdentifier},
};
use rusqlite::{params, ToSql};

use super::{Database, DatabaseError};

impl Database {
    #[allow(clippy::needless_pass_by_value)]
    pub fn add_group_info(
        &self,
        group_id: GroupIdentifier,
        group_name: impl AsRef<str> + ToSql,
        group_description: Option<String>,
        epoch: u64,
        blinded_address: BlindedAddressSecret,
    ) -> Result<(), DatabaseError> {
        self.get_connection().execute(
            "INSERT INTO group_info 
                    (group_id, epoch_id, group_name, group_description, blinded_address) 
                    VALUES (?, ?, ?, ?, ?)",
            params![
                group_id.to_bytes(),
                epoch,
                group_name,
                group_description,
                blinded_address.to_bytes()
            ],
        )?;

        Ok(())
    }

    pub fn get_group_info(
        &self,
        group_id: GroupIdentifier,
    ) -> Result<(String, Option<String>, u64, BlindedAddressSecret), DatabaseError> {
        let res: (String, Option<String>, u64, [u8; 32]) = self.get_connection().query_row(
            "SELECT group_name, group_description, epoch_id, blinded_address FROM group_info WHERE group_id = ? ORDER BY epoch_id DESC LIMIT 1",
            params![group_id.to_bytes()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )?;
        Ok((res.0, res.1, res.2, BlindedAddressSecret::from_bytes(res.3)))
    }

    pub fn get_blinded_address(
        &self,
        group_id: GroupIdentifier,
        // If epoch is None, then we resort to the latest one
        epoch: Option<u64>,
    ) -> Result<BlindedAddressSecret, DatabaseError> {
        let bytes: [u8; 32] = if let Some(epoch) = epoch {
            self.get_connection().query_row(
                "SELECT blinded_address FROM group_info WHERE group_id = ? AND epoch_id = ?",
                params![group_id.to_bytes(), epoch],
                |row| row.get(0),
            )?
        } else {
            self.get_connection().query_row(
                "SELECT blinded_address FROM group_info WHERE group_id = ? ORDER BY epoch_id DESC LIMIT 1",
                params![group_id.to_bytes()],
                |row| row.get(0),
            )?
        };

        Ok(BlindedAddressSecret::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use lib::crypto::rng::random_bytes;

    use super::*;

    #[test]
    pub fn roundtrip_group_information() {
        let db = Database::in_memory().expect("in-memory db starts");

        let group_id = GroupIdentifier::generate_id();
        let group_name = "Group name".to_string();
        let group_description = "Group description".to_string();
        let epoch = 1;
        let blinded_address_bytes = {
            let secret = random_bytes::<16>();

            BlindedAddressSecret::from_group_secret(&secret).to_bytes()
        };
        let blinded_address = BlindedAddressSecret::from_bytes(blinded_address_bytes);

        assert!(
            db.get_group_info(group_id).is_err(),
            "Getting group info for a group that doesn't exist should return an error"
        );

        assert_eq!(
            db.add_group_info(
                group_id,
                group_name.clone(),
                Some(group_description.clone()),
                epoch,
                BlindedAddressSecret::from_bytes(blinded_address_bytes),
            ),
            Ok(()),
            "Adding group info works"
        );

        assert_eq!(
            db.get_group_info(group_id).expect("No database error"),
            (
                group_name.clone(),
                Some(group_description.clone()),
                epoch,
                BlindedAddressSecret::from_bytes(blinded_address_bytes),
            )
        );

        assert_eq!(
            db.get_blinded_address(group_id, Some(epoch))
                .expect("No database error"),
            blinded_address
        );

        assert_eq!(
            db.get_blinded_address(group_id, None)
                .expect("No database error"),
            blinded_address
        );

        let new_epoch = 2;
        let new_blinded_address_bytes = {
            let secret = random_bytes::<16>();

            BlindedAddressSecret::from_group_secret(&secret).to_bytes()
        };
        let new_blinded_address = BlindedAddressSecret::from_bytes(new_blinded_address_bytes);

        assert_eq!(
            db.add_group_info(
                group_id,
                group_name.clone(),
                Some(group_description.clone()),
                new_epoch,
                BlindedAddressSecret::from_bytes(new_blinded_address_bytes),
            ),
            Ok(()),
            "Adding group info works"
        );

        assert_eq!(
            db.get_group_info(group_id).expect("No database error"),
            (
                group_name.clone(),
                Some(group_description),
                new_epoch,
                BlindedAddressSecret::from_bytes(new_blinded_address_bytes),
            )
        );

        assert_eq!(
            db.get_blinded_address(group_id, Some(epoch))
                .expect("No database error"),
            blinded_address
        );

        assert_eq!(
            db.get_blinded_address(group_id, Some(new_epoch))
                .expect("No database error"),
            new_blinded_address
        );

        assert_eq!(
            db.get_blinded_address(group_id, None)
                .expect("No database error"),
            new_blinded_address
        );
    }

    #[test]
    pub fn roundtrip_group_information_no_description() {
        let db = Database::in_memory().expect("in-memory db starts");

        let group_id = GroupIdentifier::generate_id();
        let group_name = "Group name".to_string();
        let epoch = 1;
        let blinded_address_bytes = {
            let secret = random_bytes::<16>();

            BlindedAddressSecret::from_group_secret(&secret).to_bytes()
        };

        assert_eq!(
            db.add_group_info(
                group_id,
                group_name.clone(),
                None,
                epoch,
                BlindedAddressSecret::from_bytes(blinded_address_bytes),
            ),
            Ok(()),
            "Adding group info works"
        );

        assert_eq!(
            db.get_group_info(group_id).expect("No database error"),
            (
                group_name.clone(),
                None,
                epoch,
                BlindedAddressSecret::from_bytes(blinded_address_bytes)
            )
        );
    }
}
