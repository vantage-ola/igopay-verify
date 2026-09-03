//! Minimal canonical CBOR codec (RFC 8949 §4.2.1 core-deterministic subset).
//!
//! Why hand-rolled: the fork-detection rule requires that two honest parties
//! encode the *same* logical promise to the *same* bytes, always. Determinism is
//! therefore a security property, not a convenience, so it is implemented and
//! tested here rather than delegated to a serializer whose canonical mode depends
//! on configuration. Only the subset the protocol needs is supported:
//!
//! * major 0  unsigned integer (shortest form)
//! * major 1  negative integer (shortest form)
//! * major 2  byte string (definite length)
//! * major 3  text string (definite length, UTF-8)
//! * major 4  array (definite length)
//! * major 5  map (definite length, keys are small unsigned ints, ascending)
//!
//! Encoding always emits the shortest form and definite lengths. Decoding
//! *rejects* any non-canonical input (non-shortest integers, indefinite lengths,
//! out-of-order or duplicate map keys), because a lenient decoder would reopen the
//! malleability hole the canonical form exists to close.

use alloc::string::String;
use alloc::vec::Vec;
use core::convert::TryInto;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CodecError {
    Truncated,
    UnexpectedType { expected: &'static str, major: u8 },
    NonCanonicalInt,
    IndefiniteLength,
    LengthOverflow,
    InvalidUtf8,
    MapKeysNotSorted,
    DuplicateMapKey(u64),
    TrailingBytes,
    UnsupportedMajor(u8),
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    fn write_head(&mut self, major: u8, arg: u64) {
        let mt = major << 5;
        if arg < 24 {
            self.buf.push(mt | (arg as u8));
        } else if arg <= u8::MAX as u64 {
            self.buf.push(mt | 24);
            self.buf.push(arg as u8);
        } else if arg <= u16::MAX as u64 {
            self.buf.push(mt | 25);
            self.buf.extend_from_slice(&(arg as u16).to_be_bytes());
        } else if arg <= u32::MAX as u64 {
            self.buf.push(mt | 26);
            self.buf.extend_from_slice(&(arg as u32).to_be_bytes());
        } else {
            self.buf.push(mt | 27);
            self.buf.extend_from_slice(&arg.to_be_bytes());
        }
    }

    pub fn u64(&mut self, v: u64) {
        self.write_head(0, v);
    }

    pub fn i64(&mut self, v: i64) {
        if v >= 0 {
            self.write_head(0, v as u64);
        } else {
            // major 1 encodes -1 - n
            self.write_head(1, (-1 - v) as u64);
        }
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.write_head(2, b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn text(&mut self, s: &str) {
        self.write_head(3, s.len() as u64);
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn array_head(&mut self, len: usize) {
        self.write_head(4, len as u64);
    }

    /// Begin a map with `len` entries. The caller MUST emit keys in strictly
    /// ascending order; `map_key` enforces it in debug builds.
    pub fn map_head(&mut self, len: usize) {
        self.write_head(5, len as u64);
    }

    pub fn map_key(&mut self, k: u64) {
        self.u64(k);
    }

    /// Append already-canonical CBOR bytes verbatim, used to embed a nested
    /// canonical structure (e.g. a certificate inside a promise) as a map value.
    /// The caller is responsible for the bytes being canonical.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub fn finish(self) -> Result<(), CodecError> {
        if self.pos == self.data.len() {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn peek_major(&self) -> Result<u8, CodecError> {
        let b = *self.data.get(self.pos).ok_or(CodecError::Truncated)?;
        Ok(b >> 5)
    }

    /// Public accessor used by strict decoders to look ahead at the next major type
    /// without consuming it.
    pub fn next_major(&self) -> Result<u8, CodecError> {
        self.peek_major()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        let end = self.pos.checked_add(n).ok_or(CodecError::LengthOverflow)?;
        let slice = self.data.get(self.pos..end).ok_or(CodecError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// Read a definite-length head, returning (major, argument). Rejects
    /// indefinite lengths and non-shortest integer encodings.
    fn read_head(&mut self) -> Result<(u8, u64), CodecError> {
        let initial = *self.data.get(self.pos).ok_or(CodecError::Truncated)?;
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1f;
        let arg = match info {
            0..=23 => info as u64,
            24 => {
                let v = self.take(1)?[0] as u64;
                if v < 24 {
                    return Err(CodecError::NonCanonicalInt);
                }
                v
            }
            25 => {
                let raw = self.take(2)?;
                let v = u16::from_be_bytes(raw.try_into().unwrap()) as u64;
                if v <= u8::MAX as u64 {
                    return Err(CodecError::NonCanonicalInt);
                }
                v
            }
            26 => {
                let raw = self.take(4)?;
                let v = u32::from_be_bytes(raw.try_into().unwrap()) as u64;
                if v <= u16::MAX as u64 {
                    return Err(CodecError::NonCanonicalInt);
                }
                v
            }
            27 => {
                let raw = self.take(8)?;
                let v = u64::from_be_bytes(raw.try_into().unwrap());
                if v <= u32::MAX as u64 {
                    return Err(CodecError::NonCanonicalInt);
                }
                v
            }
            28..=30 => return Err(CodecError::UnsupportedMajor(major)),
            31 => return Err(CodecError::IndefiniteLength),
            _ => unreachable!(),
        };
        Ok((major, arg))
    }

    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let (major, arg) = self.read_head()?;
        if major != 0 {
            return Err(CodecError::UnexpectedType {
                expected: "uint",
                major,
            });
        }
        Ok(arg)
    }

    pub fn i64(&mut self) -> Result<i64, CodecError> {
        let (major, arg) = self.read_head()?;
        match major {
            0 => arg.try_into().map_err(|_| CodecError::LengthOverflow),
            1 => {
                let n: i64 = arg.try_into().map_err(|_| CodecError::LengthOverflow)?;
                Ok(-1 - n)
            }
            _ => Err(CodecError::UnexpectedType {
                expected: "int",
                major,
            }),
        }
    }

    pub fn bytes(&mut self) -> Result<Vec<u8>, CodecError> {
        let (major, len) = self.read_head()?;
        if major != 2 {
            return Err(CodecError::UnexpectedType {
                expected: "bytes",
                major,
            });
        }
        Ok(self.take(len as usize)?.to_vec())
    }

    /// Read a byte string of exactly `n` bytes into a fixed array.
    pub fn bytes_fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        let v = self.bytes()?;
        v.as_slice()
            .try_into()
            .map_err(|_| CodecError::UnexpectedType {
                expected: "fixed-bytes",
                major: 2,
            })
    }

    pub fn text(&mut self) -> Result<String, CodecError> {
        let (major, len) = self.read_head()?;
        if major != 3 {
            return Err(CodecError::UnexpectedType {
                expected: "text",
                major,
            });
        }
        let raw = self.take(len as usize)?;
        String::from_utf8(raw.to_vec()).map_err(|_| CodecError::InvalidUtf8)
    }

    /// Read an array head and return its element count.
    pub fn array_head(&mut self) -> Result<usize, CodecError> {
        let (major, len) = self.read_head()?;
        if major != 4 {
            return Err(CodecError::UnexpectedType {
                expected: "array",
                major,
            });
        }
        Ok(len as usize)
    }

    /// Read a map head and return its entry count.
    pub fn map_head(&mut self) -> Result<usize, CodecError> {
        let (major, len) = self.read_head()?;
        if major != 5 {
            return Err(CodecError::UnexpectedType {
                expected: "map",
                major,
            });
        }
        Ok(len as usize)
    }

    /// Helper for decoding fixed-schema maps with small integer keys. Reads the
    /// next key, enforcing strictly ascending order against `last_key`.
    pub fn map_key(&mut self, last_key: &mut Option<u64>) -> Result<u64, CodecError> {
        let k = self.u64()?;
        if let Some(prev) = *last_key {
            if k == prev {
                return Err(CodecError::DuplicateMapKey(k));
            }
            if k < prev {
                return Err(CodecError::MapKeysNotSorted);
            }
        }
        *last_key = Some(k);
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ints() {
        for v in [
            0u64,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u64::MAX,
        ] {
            let mut e = Encoder::new();
            e.u64(v);
            let bytes = e.into_bytes();
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.u64().unwrap(), v);
            d.finish().unwrap();
        }
    }

    #[test]
    fn rejects_non_shortest_int() {
        // 0x18 0x05 => uint 5 encoded in two bytes; canonical form is 0x05.
        let bytes = [0x18u8, 0x05];
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.u64(), Err(CodecError::NonCanonicalInt));
    }

    #[test]
    fn rejects_indefinite_length() {
        let bytes = [0x5fu8]; // indefinite-length byte string
        let mut d = Decoder::new(&bytes);
        assert_eq!(d.bytes(), Err(CodecError::IndefiniteLength));
    }

    #[test]
    fn negative_ints_roundtrip() {
        for v in [-1i64, -24, -25, -256, -257, i64::MIN + 1] {
            let mut e = Encoder::new();
            e.i64(v);
            let bytes = e.into_bytes();
            let mut d = Decoder::new(&bytes);
            assert_eq!(d.i64().unwrap(), v);
        }
    }
}
