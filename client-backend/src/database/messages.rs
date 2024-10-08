use lib::{
    api::group::DeliveryStamp,
    identifiers::{AccountId, GroupIdentifier, LicksIdentifier, Uuid},
};
use rusqlite::params;

use crate::messages::{Content, MessageKind};

use super::{Database, DatabaseError};

pub struct DatabaseMessage {
    pub database_id: u64,
    pub group_id: GroupIdentifier,
    pub account_id: AccountId,
    pub server_delivery_stamp: DeliveryStamp,
    pub our_delivery_stamp: DeliveryStamp,
    pub message_kind: MessageKind,
    pub message: Content,
}

#[derive(Clone, Copy)]
pub enum Direction {
    Before,
    After,
}

/// (`id`, `account_id`, `server_timestamp`, `received_timestamp`, `message_kind`, `plaintext_content`)
type MessageSqlRow = (u64, Uuid, Uuid, Uuid, u8, String);

impl Database {
    pub fn add_message(
        &self,
        content: Content,
        sender_account_id: AccountId,
        server_delivery_timestamp: &DeliveryStamp,
        group: &GroupIdentifier,
    ) -> Result<(), DatabaseError> {
        match content {
            Content::BasicText { body } => {
                // TODO: Use our DeliveryId as the key
                let query = "
                    INSERT INTO messages (id, group_id, 
                        account_id, server_timestamp, 
                        received_timestamp, message_kind, 
                        plaintext_content, reply_message_timestamp)
                    VALUES (NULL, ?1, ?2, ?3, ?4, ?5, ?6, NULL)
                ";

                let group_id = group.to_bytes();
                let account_id = sender_account_id.as_uuid();
                let server_timestamp = server_delivery_timestamp.as_bytes();
                let received_timestamp = DeliveryStamp::generate().to_vec();
                let message_kind: u8 = MessageKind::PlainText.into();
                let plaintext_content = body;

                self.get_connection().execute(
                    query,
                    params![
                        group_id,
                        account_id,
                        server_timestamp,
                        received_timestamp,
                        message_kind,
                        plaintext_content,
                    ],
                )?;
            }
        };

        Ok(())
    }

    pub fn get_last_message(
        &self,
        group: GroupIdentifier,
    ) -> Result<DatabaseMessage, DatabaseError> {
        let query = "
            SELECT id, 
                account_id, server_timestamp, 
                received_timestamp, message_kind, 
                plaintext_content
                FROM messages
                WHERE group_id = ?
                ORDER BY id DESC
                LIMIT 1
        ";

        let group_id = group.to_bytes();

        let row: MessageSqlRow =
            self.get_connection()
                .query_row(query, params![group_id], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                })?;

        Self::convert_values_to_message(row, group)
    }

    pub const MAX_MESSAGE_ID: u64 = i64::MAX as u64;

    pub fn get_many_messages(
        &self,
        group: GroupIdentifier,
        id: u64,
        direction: Direction,
        count: usize,
    ) -> Result<Vec<Result<DatabaseMessage, ()>>, DatabaseError> {
        let query_before = "
            SELECT id, 
                account_id, server_timestamp, 
                received_timestamp, message_kind, 
                plaintext_content
                FROM messages
                WHERE group_id = ? AND id < ?
                ORDER BY id DESC
                LIMIT ?
        ";

        let query_after = "
            SELECT id, 
                account_id, server_timestamp, 
                received_timestamp, message_kind, 
                plaintext_content
                FROM messages
                WHERE group_id = ? AND id > ? 
                ORDER BY id ASC
                LIMIT ?
        ";
        let query = match direction {
            Direction::Before => query_before,
            Direction::After => query_after,
        };
        let connection = self.get_connection();
        let mut statement = connection.prepare(query)?;
        let rows = statement.query_map(params![group.to_bytes(), id, count], |row| {
            Ok((
                row.get::<_, u64>(0)?,
                row.get::<_, Uuid>(1)?,
                row.get::<_, Uuid>(2)?,
                row.get::<_, Uuid>(3)?,
                row.get::<_, u8>(4)?,
                row.get::<_, String>(5)?,
            ))
        })?;

        let mut fin = Vec::new();
        for row in rows {
            match row {
                Ok(row) => fin.push(Self::convert_values_to_message(row, group).map_err(|_| ())),
                Err(_e) => {
                    fin.push(Err(()));
                }
            }
        }
        Ok(fin)
    }

    fn convert_values_to_message(
        row: MessageSqlRow,
        group_id: GroupIdentifier,
    ) -> Result<DatabaseMessage, DatabaseError> {
        let (id, account_id, server_timestamp, received_timestamp, message_kind, plaintext_content) =
            row;
        let message_kind =
            MessageKind::try_from(message_kind).map_err(|_| DatabaseError::CorruptedData)?;
        Ok(DatabaseMessage {
            database_id: id,
            group_id,
            account_id: account_id.into(),
            server_delivery_stamp: DeliveryStamp::try_from(server_timestamp)
                .map_err(|()| DatabaseError::CorruptedData)?,
            our_delivery_stamp: DeliveryStamp::try_from(received_timestamp)
                .map_err(|()| DatabaseError::CorruptedData)?,
            message_kind,
            message: match message_kind {
                MessageKind::PlainText => Content::BasicText {
                    body: plaintext_content,
                },
            },
        })
    }
}
