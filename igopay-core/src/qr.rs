//! QR transport codec (D1): unpadded RFC 4648 base32, uppercase.
//!
//! Phase 0 measured that raw QR *byte* mode mojibakes on real budget-phone
//! decoders, while base32 in QR **alphanumeric** mode survives arbitrary scanners
//! and is actually *denser* on the wire despite producing more characters (5.5
//! bits/char alphanumeric beats 8 bits/char byte mode once mode overhead is counted
//! — `09-phase0-results.md` §1, decision D1). So the bytes a [`crate::Promise`]
//! encodes to are never placed in a QR directly: they are base32-encoded first.
//!
//! Why implemented here, not left to the app:
//!   * it is part of the wire contract — Android and iOS must agree on the exact
//!     string, so it belongs in the shared core and is covered by the golden
//!     vectors, not reimplemented twice;
//!   * `'='` padding is **not** in the QR alphanumeric charset (`0-9 A-Z` plus
//!     `` $%*+-./: `` and space), so this codec emits **unpadded** base32. The
//!     original length is recoverable from the decoded byte count, exactly as the
//!     Phase 0 tool (`tools/qr_capacity.py`) does.
//!
//! The alphabet is the standard RFC 4648 base32 set `A–Z2–7`, all of which are QR
//! alphanumeric characters, so an encoded payload always fits alphanumeric mode.

use alloc::string::String;
use alloc::vec::Vec;

/// RFC 4648 base32 alphabet (uppercase, no padding). Index → character.
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Sentinel for "not a base32 character" in the reverse lookup table.
const INVALID: u8 = 0xFF;

/// Reverse lookup: ASCII byte → 5-bit value, or [`INVALID`]. Built at compile time
/// so decoding is a table lookup with no allocation and no per-call setup.
const REV: [u8; 256] = build_rev();

const fn build_rev() -> [u8; 256] {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < 32 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// Errors from decoding a QR transport payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrError {
    /// A character outside the base32 alphabet (position and byte reported).
    InvalidChar { index: usize, byte: u8 },
    /// The encoded length is not a valid unpadded base32 length. Valid remainders of
    /// the char count mod 8 are 0, 2, 4, 5, 7; the others (1, 3, 6) cannot occur for
    /// any byte input and signal a truncated or corrupt payload.
    InvalidLength { chars: usize },
    /// Non-zero bits in the final partial group. A canonical unpadded base32 encoder
    /// leaves the unused trailing bits zero; anything else is non-canonical input and
    /// is rejected so a payload has exactly one valid encoding (same discipline as
    /// the CBOR codec).
    NonCanonicalTrailingBits,
}

/// Encode bytes as an unpadded, uppercase base32 string ready for a QR in
/// alphanumeric mode.
pub fn to_qr_payload(data: &[u8]) -> String {
    // Every 5 input bytes -> 8 output chars; a trailing partial group emits
    // ceil(bits/5) chars with no padding.
    let out_len = data.len().div_ceil(5) * 8;
    let mut out = Vec::with_capacity(out_len);

    for chunk in data.chunks(5) {
        // Pack up to 5 bytes into a 40-bit buffer, MSB-first.
        let mut buf: u64 = 0;
        for &b in chunk {
            buf = (buf << 8) | b as u64;
        }
        // Left-align so the first 5-bit group is in the top bits of 40.
        let bits = chunk.len() * 8;
        buf <<= 40 - bits;
        // Number of 5-bit groups this chunk produces (ceil).
        let groups = bits.div_ceil(5);
        for g in 0..groups {
            let shift = 40 - 5 * (g + 1);
            let idx = ((buf >> shift) & 0x1f) as usize;
            out.push(ALPHABET[idx]);
        }
    }

    // out is pure ASCII from ALPHABET, so this is always valid UTF-8.
    String::from_utf8(out).expect("base32 output is ASCII")
}

/// Decode an unpadded base32 string back to bytes. Strict: rejects out-of-alphabet
/// characters, impossible lengths, and non-zero trailing bits (non-canonical input).
///
/// The input is treated case-sensitively as uppercase, because a QR alphanumeric
/// segment only carries uppercase and the encoder only ever emits uppercase; a
/// lowercase byte is therefore genuinely out-of-charset, not a formatting nicety.
pub fn from_qr_payload(s: &str) -> Result<Vec<u8>, QrError> {
    let chars = s.as_bytes();
    let n = chars.len();

    // Reject char counts that no byte input can produce. For unpadded base32 the
    // valid remainders of n mod 8 are {0, 2, 4, 5, 7}.
    match n % 8 {
        1 | 3 | 6 => return Err(QrError::InvalidLength { chars: n }),
        _ => {}
    }

    let mut out = Vec::with_capacity(n / 8 * 5 + 4);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;

    for (index, &c) in chars.iter().enumerate() {
        let val = REV[c as usize];
        if val == INVALID {
            return Err(QrError::InvalidChar { index, byte: c });
        }
        buf = (buf << 5) | val as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            let byte = (buf >> bits) & 0xff;
            out.push(byte as u8);
        }
    }

    // Any leftover (< 8) bits must be zero for canonical unpadded base32.
    if bits > 0 {
        let mask = (1u64 << bits) - 1;
        if buf & mask != 0 {
            return Err(QrError::NonCanonicalTrailingBits);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn rfc4648_test_vectors() {
        // RFC 4648 §10 base32 vectors, with padding stripped.
        let cases: &[(&[u8], &str)] = &[
            (b"", ""),
            (b"f", "MY"),
            (b"fo", "MZXQ"),
            (b"foo", "MZXW6"),
            (b"foob", "MZXW6YQ"),
            (b"fooba", "MZXW6YTB"),
            (b"foobar", "MZXW6YTBOI"),
        ];
        for (bytes, expected) in cases {
            assert_eq!(&to_qr_payload(bytes), expected, "encode {:?}", bytes);
            assert_eq!(
                &from_qr_payload(expected).unwrap(),
                bytes,
                "decode {}",
                expected
            );
        }
    }

    #[test]
    fn roundtrip_all_lengths() {
        // Every length 0..=40 of a byte ramp must round-trip exactly.
        for len in 0..=40usize {
            let data: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(37)).collect();
            let encoded = to_qr_payload(&data);
            assert_eq!(from_qr_payload(&encoded).unwrap(), data, "len {}", len);
        }
    }

    #[test]
    fn output_is_alphanumeric_charset_only() {
        // Everything the encoder emits must be a QR alphanumeric character so the
        // payload always fits alphanumeric mode (D1). A–Z and 2–7 all qualify.
        let data: Vec<u8> = (0..=255u8).collect();
        let encoded = to_qr_payload(&data);
        for ch in encoded.bytes() {
            let ok = ch.is_ascii_uppercase() || (b'2'..=b'7').contains(&ch);
            assert!(ok, "char {:?} is not in the base32 QR alphabet", ch as char);
        }
    }

    #[test]
    fn rejects_out_of_alphabet_char() {
        // '1', '8', '0' and lowercase are not in RFC 4648 base32. All strings here
        // are 8 chars (a valid base32 length) so the char check, not the length
        // check, is what trips.
        for bad in ["MZXW6YT1", "mzxw6ytb", "MZXW6YT8"] {
            assert!(
                matches!(from_qr_payload(bad), Err(QrError::InvalidChar { .. })),
                "{} should be InvalidChar",
                bad
            );
        }
    }

    #[test]
    fn rejects_impossible_length() {
        // A single trailing char (n % 8 == 1) is not a valid base32 length.
        assert_eq!(
            from_qr_payload("MZXW6YTBO"), // 9 chars -> 9 % 8 == 1
            Err(QrError::InvalidLength { chars: 9 })
        );
    }

    #[test]
    fn rejects_non_canonical_trailing_bits() {
        // "MZ" decodes 'f' from 10 bits; the low 2 bits must be zero. "M" + a char
        // whose low bits are set makes the trailing bits non-zero.
        // 'M'=12 (01100), 'Z'=25 (11001) -> 0110011001, byte 01100110='f', leftover 01.
        // Flip the last char so leftover bits are non-zero: 'M','B' -> 'B'=1 (00001).
        // 0110000001 -> byte 01100000, leftover 01 -> non-canonical.
        assert_eq!(
            from_qr_payload("MB"),
            Err(QrError::NonCanonicalTrailingBits)
        );
    }

    #[test]
    fn empty_roundtrips() {
        assert_eq!(to_qr_payload(&[]), "");
        assert_eq!(from_qr_payload("").unwrap(), vec![]);
    }
}
