//! Hex, and the "one artefact per line" text container every published file uses.
//!
//! This is transport plumbing, not protocol: nothing here verifies anything, and nothing
//! here is allowed to. It lives in the core for one structural reason — the parties that
//! read and write these files are *deliberately different parties*. The issuer publishes a
//! mirror; a witness keeps its own state; an auditor reads both. A witness that had to link
//! the issuer's crate in order to decode a hex line would be linking the code of the party
//! it exists to check, which is exactly the coupling B7 is trying to remove.
//!
//! So: one implementation, in the crate everyone already depends on, and `igopay-issuer`
//! keeps its zero-third-party-dependency tree by re-exporting it rather than owning it.

use alloc::string::String;
use alloc::vec::Vec;

/// Lowercase hex. Always emitted lowercase so a published file has one canonical appearance.
pub fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    s
}

/// Decode hex, accepting either case.
///
/// Liberal on input, canonical on output. Case has no security consequence here — the bytes
/// it decodes to are canonical CBOR and signature-checked either way — and refusing an
/// uppercase file would only make a hand-edited file harder to fix.
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || s.is_empty() {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Non-empty, non-comment lines with their 1-based line numbers.
///
/// `#` starts a comment so a published file can carry a note without breaking the parser.
/// Blank lines are ignored, which keeps a stray trailing newline from being an error.
pub fn hex_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty() && !l.starts_with('#'))
}

/// Render a sequence of artefacts as one hex line each, in the order given.
///
/// Callers append to these files and must never rewrite them, so the order is the caller's
/// to decide and this function does not sort.
pub fn render_lines<I>(items: I) -> String
where
    I: IntoIterator,
    I::Item: AsRef<[u8]>,
{
    let mut s = String::new();
    for item in items {
        s.push_str(&to_hex(item.as_ref()));
        s.push('\n');
    }
    s
}
