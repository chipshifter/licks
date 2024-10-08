//! Serializer and Deserializer

#[cfg(test)]
pub(crate) mod serde_test;

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::mls::utilities::error::{Error, Result};

#[inline]
pub fn deserialize_varint<B: Buf>(buf: &mut B) -> Result<u32> {
    if !buf.has_remaining() {
        return Err(Error::BufferTooSmall);
    }
    let b = buf.get_u8();

    let prefix = b >> 6;
    if prefix == 3 {
        return Err(Error::InvalidVariableLengthIntegerPrefix);
    }

    let n = 1 << prefix;
    let mut v = u32::from(b & 0x3F);
    for _ in 0..n - 1 {
        if !buf.has_remaining() {
            return Err(Error::BufferTooSmall);
        }
        let b = buf.get_u8();
        v = (v << 8) + u32::from(b);
    }

    if prefix >= 1 && v < 1u32 << (8 * (n / 2) - 2) {
        return Err(Error::MinimumEncodingWasNotUsed);
    }

    Ok(v)
}

#[allow(clippy::cast_possible_truncation)] // truncation is intended here
#[inline]
pub fn serialize_varint<B: BufMut>(n: u32, buf: &mut B) -> Result<()> {
    if n < (1 << 6) {
        buf.put_u8(n as u8);
    } else if n < (1 << 14) {
        buf.put_u16(0b01 << 14 | (n as u16));
    } else if n < (1 << 30) {
        buf.put_u32(0b10 << 30 | n);
    } else {
        return Err(Error::VarintExceeds30Bits);
    }
    Ok(())
}

#[inline]
pub fn deserialize_opaque_vec<B: Buf>(buf: &mut B) -> Result<Bytes> {
    let n = deserialize_varint(buf)? as usize;
    if buf.remaining() < n {
        return Err(Error::BufferTooSmall);
    }

    Ok(buf.copy_to_bytes(n))
}

#[inline]
pub fn serialize_opaque_vec<B: BufMut>(v: &[u8], buf: &mut B) -> Result<()> {
    let len = u32::try_from(v.len()).map_err(|_| Error::OpaqueSizeExceedsMaximumValueOfU32)?;

    serialize_varint(len, buf)?;

    buf.put(v);

    Ok(())
}

#[inline]
pub fn deserialize_vector<B: Buf>(
    buf: &mut B,
    mut f: impl FnMut(&mut Bytes) -> Result<()>,
) -> Result<()> {
    let n = deserialize_varint(buf)? as usize;
    if buf.remaining() < n {
        return Err(Error::BufferTooSmall);
    }

    let mut v = buf.copy_to_bytes(n);
    let ss = &mut v;
    while ss.has_remaining() {
        f(ss)?;
    }
    Ok(())
}

#[inline]
pub fn serialize_vector<B: BufMut>(
    n: usize,
    buf: &mut B,
    mut f: impl FnMut(usize, &mut BytesMut) -> Result<()>,
) -> Result<()> {
    // We don't know the total size in advance, and the vector is prefixed with
    // a varint, so we can't avoid the temporary buffer here
    let mut child = BytesMut::new();
    for i in 0..n {
        f(i, &mut child)?;
    }

    let raw = child.freeze();

    serialize_opaque_vec(&raw, buf)
}

#[inline]
pub fn deserialize_optional<B: Buf>(buf: &mut B) -> Result<bool> {
    if !buf.has_remaining() {
        return Err(Error::BufferTooSmall);
    }
    let b = buf.get_u8();

    match b {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(Error::InvalidOptionalValue),
    }
}

#[inline]
pub fn serialize_optional<B: BufMut>(present: bool, buf: &mut B) -> Result<()> {
    let n: u8 = u8::from(present);
    buf.put_u8(n);
    Ok(())
}

pub trait Deserializer {
    fn deserialize<B>(buf: &mut B) -> Result<Self>
    where
        Self: Sized,
        B: Buf;

    fn deserialize_exact(buf: impl AsRef<[u8]>) -> Result<Self>
    where
        Self: Sized,
    {
        let mut buf = buf.as_ref();
        Self::deserialize(&mut buf)
    }
}

pub trait Serializer {
    fn serialize<B>(&self, buf: &mut B) -> Result<()>
    where
        Self: Sized,
        B: BufMut;

    fn serialize_detached(&self) -> Result<Bytes>
    where
        Self: Sized,
    {
        let mut buf = BytesMut::new();
        self.serialize(&mut buf)?;
        Ok(buf.freeze())
    }
}
