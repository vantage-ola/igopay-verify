//! The public mirror format (B7): the issuer's log as plain text anyone can clone.
//!
//! `checkpoint` makes the issuer's history self-consistent or provably not. `anchor` is the
//! seam for putting the head where a stranger can read it. This module is the cheapest
//! implementation of that seam's *publication* half: the log rendered as text, in a public
//! git repository, one line per entry.
//!
//! Unglamorous on purpose. It costs nothing, needs no account to read, no token, and no
//! trust in us beyond what the signatures already carry — an auditor clones the repository,
//! parses it, re-verifies every signature and link with [`CheckpointLog::resume`], and
//! compares the head against what their own device was told. What it buys is the thing a
//! chain alone cannot: a single place everyone reads, which is what turns "detectable in
//! principle" into "detected in practice".
//!
//! ## Why text, and why one line per entry
//!
//! Hex, one checkpoint per line, position `n` on line `n`. A publication is then exactly
//! **one added line** in a diff, so an append is visually distinguishable from a rewrite by
//! anyone reading the repository's history — including someone who understands none of the
//! cryptography. A compact binary blob would be smaller and would hide that completely.
//!
//! The cost is measured, not assumed: a checkpoint is under 200 bytes, so about 360
//! characters a line, and hourly publication for a year is roughly 3 MB of text.
//!
//! ## Two files, both append-only
//!
//! Cosignatures ([`crate::anchor::WitnessAnchor`]) arrive *after* a checkpoint is published —
//! a witness might reply seconds later or the next morning. Storing them inline would mean
//! going back and editing a line that had already been committed, which destroys exactly the
//! property this format exists for. So they live in their own file, one per line, in whatever
//! order they arrive; each names the checkpoint and issuer it attests to, so nothing about
//! their position matters. A late attestation is a new line, never an edit.
//!
//! ## What is deliberately *not* mirrored
//!
//! The block lists themselves. A checkpoint carries digests only — no payer keys, no
//! amounts, nothing about anybody's payments — while a block list carries the public keys of
//! blocked payers. Mirroring lists would publish a permanent, world-readable blacklist of
//! pseudonymous keys, which is a disclosure decision nobody should make by accident. The
//! digests are enough for the job: anyone can check that the list they hold is the one that
//! was published.

use crate::checkpoint::CheckpointLog;
use igopay_core::checkpoint::Checkpoint;
use igopay_core::crypto::PubKeyBytes;
use igopay_core::witness::Cosignature;
use igopay_core::Hash;

/// The log: one checkpoint per line, line `n` holding position `n`.
pub const CHECKPOINTS_FILE: &str = "checkpoints.hex";
/// Cosignatures, one per line, append-only in arrival order.
pub const COSIGNATURES_FILE: &str = "cosignatures.hex";
/// The head's digest — the one value to timestamp externally.
pub const HEAD_FILE: &str = "head.txt";
/// The issuer's public key, so a reader needs nothing from us to verify.
pub const ISSUER_KEY_FILE: &str = "issuer.pub";
/// Trusted witness keys, one per line. May be empty; an empty file is an honest statement.
pub const WITNESSES_FILE: &str = "witnesses.txt";

/// Why a mirror could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorError {
    /// A line was not hex, or had an odd number of digits.
    BadHex { line: usize },
    /// A line was hex but not a canonical artefact of the expected type.
    BadArtefact { line: usize },
    /// Line `n` did not hold the checkpoint at position `n`. The log is contiguous from 0 by
    /// construction, so this is either a dropped entry or a hand-edited file.
    OutOfOrder { line: usize, seq: u64 },
    /// A key file did not hold a 33-byte SEC1 public key.
    BadKey { line: usize },
    /// `head.txt` did not match the digest of the last checkpoint.
    HeadMismatch { expected: Hash, found: Hash },
}

impl std::fmt::Display for MirrorError {
    /// Readable, because the first consumer of these messages is a stranger auditing a
    /// mirror, not a Rust programmer. Digests print as hex rather than as byte arrays.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MirrorError::BadHex { line } => write!(f, "line {line}: not valid hex"),
            MirrorError::BadArtefact { line } => {
                write!(f, "line {line}: decodes, but is not a canonical artefact")
            }
            MirrorError::OutOfOrder { line, seq } => write!(
                f,
                "line {line} holds position {seq}, so an entry was dropped, added or reordered"
            ),
            MirrorError::BadKey { line } => {
                write!(f, "line {line}: not a 33-byte SEC1 public key")
            }
            MirrorError::HeadMismatch { expected, found } => write!(
                f,
                "head names {}, but the log ends at {}",
                to_hex(found),
                to_hex(expected)
            ),
        }
    }
}

impl std::error::Error for MirrorError {}

// ---------------------------------------------------------------------------
// Hex and the line container.
//
// Re-exported from `igopay_core::hex` rather than owned here. `igopay-issuer` still has
// exactly one dependency — `igopay-core` — so the supply chain of the component that decides
// who gets blocked stays trivially auditable; and a witness, which must not link the issuer's
// crate at all, gets the same decoder from the same place. One implementation, no drift
// between what the issuer writes and what a witness or auditor reads.
// ---------------------------------------------------------------------------

pub use igopay_core::hex::{from_hex, to_hex};
use igopay_core::hex::{hex_lines as content_lines, render_lines};

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Render the log: one checkpoint per line, in position order.
pub fn render_checkpoints(log: &CheckpointLog) -> String {
    render_lines(log.entries().iter().map(|cp| cp.encode()))
}

/// Render cosignatures in the order given. Callers append; they do not rewrite.
pub fn render_cosignatures(cosignatures: &[Cosignature]) -> String {
    render_lines(cosignatures.iter().map(|c| c.encode()))
}

/// The head's digest, or an empty string for a log with no entries.
pub fn render_head(log: &CheckpointLog) -> String {
    match log.head() {
        Some(cp) => {
            let mut s = to_hex(&cp.body_digest());
            s.push('\n');
            s
        }
        None => String::new(),
    }
}

/// A public key as a hex line.
pub fn render_key(key: &PubKeyBytes) -> String {
    let mut s = to_hex(key);
    s.push('\n');
    s
}

/// Witness keys, one per line, ascending so the file has one canonical form.
pub fn render_witnesses(keys: &[PubKeyBytes]) -> String {
    let mut sorted: Vec<&PubKeyBytes> = keys.iter().collect();
    sorted.sort_unstable();
    render_lines(sorted)
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse the log file into checkpoints, enforcing that position `n` sits on line `n`.
///
/// This does **no** cryptography: it is a container format, and a container that verified
/// signatures would tempt a caller into thinking parsing was enough. Hand the result to
/// [`CheckpointLog::resume`], which re-checks every signature and every link.
pub fn parse_checkpoints(text: &str) -> Result<Vec<Checkpoint>, MirrorError> {
    let mut out = Vec::new();
    for (line, content) in content_lines(text) {
        let bytes = from_hex(content).ok_or(MirrorError::BadHex { line })?;
        let cp = Checkpoint::from_bytes(&bytes).map_err(|_| MirrorError::BadArtefact { line })?;
        let expected = out.len() as u64;
        if cp.seq != expected {
            return Err(MirrorError::OutOfOrder { line, seq: cp.seq });
        }
        out.push(cp);
    }
    Ok(out)
}

/// Parse the cosignature file. Order is not significant: each entry names what it attests to.
pub fn parse_cosignatures(text: &str) -> Result<Vec<Cosignature>, MirrorError> {
    let mut out = Vec::new();
    for (line, content) in content_lines(text) {
        let bytes = from_hex(content).ok_or(MirrorError::BadHex { line })?;
        let c = Cosignature::from_bytes(&bytes).map_err(|_| MirrorError::BadArtefact { line })?;
        out.push(c);
    }
    Ok(out)
}

/// Parse a file of public keys, one per line.
pub fn parse_keys(text: &str) -> Result<Vec<PubKeyBytes>, MirrorError> {
    let mut out = Vec::new();
    for (line, content) in content_lines(text) {
        let bytes = from_hex(content).ok_or(MirrorError::BadHex { line })?;
        let key: PubKeyBytes = bytes
            .as_slice()
            .try_into()
            .map_err(|_| MirrorError::BadKey { line })?;
        out.push(key);
    }
    Ok(out)
}

/// Parse a single public key.
pub fn parse_key(text: &str) -> Option<PubKeyBytes> {
    parse_keys(text).ok()?.into_iter().next()
}

/// Parse `head.txt`. `None` for an empty file, which is a log with no entries.
pub fn parse_head(text: &str) -> Result<Option<Hash>, MirrorError> {
    match content_lines(text).next() {
        None => Ok(None),
        Some((line, content)) => {
            let bytes = from_hex(content).ok_or(MirrorError::BadHex { line })?;
            let digest: Hash = bytes
                .as_slice()
                .try_into()
                .map_err(|_| MirrorError::BadKey { line })?;
            Ok(Some(digest))
        }
    }
}

/// Check `head.txt` against the log it claims to summarise.
///
/// Worth its own check because the head file is what gets timestamped externally. If it named
/// anything other than the log's last entry, the timestamp would be pinning a history nobody
/// published.
pub fn check_head(entries: &[Checkpoint], head: Option<Hash>) -> Result<(), MirrorError> {
    match (entries.last(), head) {
        (None, None) => Ok(()),
        (Some(cp), Some(found)) if cp.body_digest() == found => Ok(()),
        (Some(cp), Some(found)) => Err(MirrorError::HeadMismatch {
            expected: cp.body_digest(),
            found,
        }),
        (Some(cp), None) => Err(MirrorError::HeadMismatch {
            expected: cp.body_digest(),
            found: [0u8; 32],
        }),
        (None, Some(found)) => Err(MirrorError::HeadMismatch {
            expected: [0u8; 32],
            found,
        }),
    }
}

// ---------------------------------------------------------------------------
// Attestation coverage, as a reader sees it
// ---------------------------------------------------------------------------

/// What the mirror says about one log position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionCoverage {
    pub seq: u64,
    pub epoch: u64,
    /// Distinct trusted witnesses whose cosignature for this position verifies.
    pub witnesses: usize,
}

/// Which positions are attested, according to the cosignatures in the mirror.
///
/// Every cosignature is re-verified against the issuer and witness keys read from the mirror
/// itself, so a reader who clones the repository can reach this conclusion without asking
/// anybody anything. Cosignatures for unknown witnesses, other issuers, or checkpoints not in
/// the log are ignored and counted as `unknown`.
pub fn coverage<V: igopay_core::crypto::Verifier>(
    entries: &[Checkpoint],
    cosignatures: &[Cosignature],
    issuer_pubkey: &PubKeyBytes,
    trusted_witnesses: &[PubKeyBytes],
    verifier: &V,
) -> (Vec<PositionCoverage>, usize) {
    let mut per_position: Vec<PositionCoverage> = entries
        .iter()
        .map(|cp| PositionCoverage {
            seq: cp.seq,
            epoch: cp.epoch,
            witnesses: 0,
        })
        .collect();
    // Distinct (position, witness) pairs, so a repeated cosignature cannot inflate a count.
    let mut counted: Vec<(u64, PubKeyBytes)> = Vec::new();
    let mut unknown = 0;

    for c in cosignatures {
        if &c.issuer_pubkey != issuer_pubkey || !trusted_witnesses.contains(&c.witness_pubkey) {
            unknown += 1;
            continue;
        }
        let Some(idx) = entries
            .iter()
            .position(|cp| cp.body_digest() == c.checkpoint_digest)
        else {
            unknown += 1;
            continue;
        };
        if c.verify(verifier).is_err() {
            unknown += 1;
            continue;
        }
        let key = (entries[idx].seq, c.witness_pubkey);
        if counted.contains(&key) {
            continue;
        }
        counted.push(key);
        per_position[idx].witnesses += 1;
    }

    (per_position, unknown)
}
