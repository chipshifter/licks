use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::mls::framing::proposal::ProposalOrRef;
use crate::mls::ratchet_tree::UpdatePath;
use crate::mls::utilities::error::Result;
use crate::mls::utilities::serde::{
    deserialize_optional, deserialize_vector, serialize_optional, serialize_vector, Deserializer,
    Serializer,
};

#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct Commit {
    pub(crate) proposals: Vec<ProposalOrRef>,
    pub(crate) path: Option<UpdatePath>,
}

impl Deserializer for Commit {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf,
    {
        let mut proposals = vec![];
        deserialize_vector(buf, |b: &mut Bytes| -> Result<()> {
            proposals.push(ProposalOrRef::deserialize(b)?);
            Ok(())
        })?;

        let has_path = deserialize_optional(buf)?;
        let path = if has_path {
            Some(UpdatePath::deserialize(buf)?)
        } else {
            None
        };

        Ok(Self { proposals, path })
    }
}

impl Serializer for Commit {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut,
    {
        serialize_vector(
            self.proposals.len(),
            buf,
            |i: usize, b: &mut BytesMut| -> Result<()> { self.proposals[i].serialize(b) },
        )?;
        serialize_optional(self.path.is_some(), buf)?;
        if let Some(update_path) = &self.path {
            update_path.serialize(buf)?;
        }

        Ok(())
    }
}
