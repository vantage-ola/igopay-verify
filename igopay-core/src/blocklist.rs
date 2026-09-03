//! Compact block list (B13): a Bloom filter for the bulk of revoked payers plus an
//! exact recent-fork set. Offline-carriable and bounded, unlike an unbounded log.
//!
//! A Bloom filter has false positives but never false negatives, which is the safe
//! direction here: a payer that IS on the list is always caught; the cost is that a
//! small fraction of clean payers get spuriously flagged and must be resolved
//! online. The exact recent set covers the freshest forks with zero false positives
//! so the newest known bad actors are never merely "probably" blocked.
//!
//! ## Publication
//!
//! [`SignedBlockList`] is the wire artefact an issuer publishes and a device
//! installs. It lives here, next to the filter, for the same reason verification
//! does: the publisher and every consumer must agree on the filter geometry and the
//! hash positions byte-for-byte, and two implementations would eventually disagree
//! about whether a payer is on the list.
//!
//! Three properties matter more than the compression:
//!
//! 1. **It is signed.** A block list tells an offline device to refuse someone's
//!    money. An unsigned one would let anyone censor any payer at will, which is a
//!    denial of service against honest users, so the issuer signs the body and the
//!    device verifies against the issuer key it already holds.
//! 2. **It cannot be rolled back.** `epoch` is monotonic and an install requires
//!    *strictly greater* than the epoch already held. Without that, replaying an
//!    old list would silently un-block a payer who has since been caught.
//! 3. **Expiry never fails open.** `not_after` marks the list stale, and staleness
//!    is advisory: it means "the *absence* of an entry is less trustworthy now, be
//!    more conservative", never "ignore the entries". No code path here drops an
//!    entry because a list aged out — otherwise waiting for expiry would be a way
//!    to get un-blocked. That is also why [`SignedBlockList::verify_and_open`]
//!    takes no clock at all.

use crate::codec::{CodecError, Decoder, Encoder};
use crate::crypto::{CryptoError, PubKeyBytes, SigBytes, Verifier};
use crate::types::{DecodeError, Hash};
use alloc::collections::BTreeSet;
use alloc::vec;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Largest filter a device will accept, in bytes (1 MiB, i.e. 8,388,608 bits —
/// roughly 800k blocked payers at 10 bits each).
///
/// This is a decoder cap, not a policy: a low-end Android Go device must not be
/// talked into allocating an arbitrary buffer by a hostile or buggy publisher.
pub const MAX_FILTER_BYTES: usize = 1 << 20;

/// Largest exact-recent set a device will accept.
pub const MAX_EXACT_RECENT: usize = 4096;

/// Upper bound on hash probes a device will accept. A larger `num_hashes` costs
/// only verification time, so an absurd value is a slow-path DoS against exactly
/// the cheap hardware this protocol targets.
pub const MAX_HASHES: u32 = 32;

/// Why a block list was refused, or could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockListError {
    Decode(DecodeError),
    /// `num_bits`, `num_hashes` and the bit buffer length disagree, or a value is
    /// structurally impossible (zero bits, zero probes).
    BadGeometry,
    /// The filter or the exact set exceeds the device-side caps above.
    TooLarge,
    /// `exact_recent` was not strictly ascending — either non-canonical ordering
    /// or a duplicated key.
    ExactSetNotSorted,
    /// The body was not signed by the expected issuer key.
    BadIssuerSignature,
    /// The signature was well-formed but high-S. Rejected everywhere in this
    /// protocol; see [`crate::crypto`].
    MalleableSignature,
    /// The offered epoch is not strictly greater than the epoch already held. This
    /// is the rollback guard, and it fires on an equal epoch too.
    StaleEpoch {
        current: u64,
        offered: u64,
    },
    /// `not_after` precedes `issued_at`, so the validity window is meaningless and
    /// staleness cannot be judged.
    InvertedWindow,
}

impl From<DecodeError> for BlockListError {
    fn from(e: DecodeError) -> Self {
        BlockListError::Decode(e)
    }
}

impl From<CodecError> for BlockListError {
    fn from(e: CodecError) -> Self {
        BlockListError::Decode(DecodeError::Codec(e))
    }
}

/// Number of hash probes for a given bits-per-item budget: `bits_per_item * ln 2`,
/// computed in integers.
///
/// Deliberately integer-only. The optimal-`k` formula wants a logarithm, but the
/// result feeds the filter *geometry*, which is part of the wire format — and
/// floating-point rounding that differs between an x86 server and an ARM phone
/// would produce two filters that disagree about which bits to set. `no_std` also
/// has no `f64::ln` without pulling in libm. Integers sidestep both.
///
/// Resulting false-positive rates, for reference:
/// 8 bits/item → k=5, ~2.2%; 10 → k=6, ~0.9%; 12 → k=8, ~0.3%; 16 → k=11, ~0.05%.
pub const fn hashes_for_bits_per_item(bits_per_item: usize) -> u32 {
    let k = (bits_per_item * 693) / 1000;
    if k < 1 {
        1
    } else if k > MAX_HASHES as usize {
        MAX_HASHES
    } else {
        k as u32
    }
}

/// A fixed-size Bloom filter keyed by SEC1-compressed public keys.
#[derive(Debug, Clone)]
pub struct BlockList {
    bits: Vec<u8>,
    num_bits: usize,
    num_hashes: u32,
    /// Exact recent-fork set. `BTreeSet` (not `HashSet`) so the whole crate is
    /// `no_std` + `alloc` only — no hasher, no OS RNG for hash seeding. Its
    /// ascending iteration order is also the canonical wire order.
    exact_recent: BTreeSet<PubKeyBytes>,
}

impl BlockList {
    /// Create an empty list with `num_bits` bits (rounded up to a byte) and
    /// `num_hashes` hash probes.
    pub fn new(num_bits: usize, num_hashes: u32) -> Self {
        let num_bits = num_bits.max(8);
        let num_hashes = num_hashes.max(1);
        BlockList {
            bits: vec![0u8; num_bits.div_ceil(8)],
            num_bits,
            num_hashes,
            exact_recent: BTreeSet::new(),
        }
    }

    /// Create an empty list sized for `num_items` entries at `bits_per_item`, with
    /// the matching probe count from [`hashes_for_bits_per_item`].
    pub fn sized_for(num_items: usize, bits_per_item: usize) -> Self {
        let bits_per_item = bits_per_item.max(1);
        let num_bits = num_items.saturating_mul(bits_per_item).max(8);
        BlockList::new(num_bits, hashes_for_bits_per_item(bits_per_item))
    }

    /// Derive `num_hashes` bit positions for a key using double hashing over one
    /// SHA-256 digest (Kirsch–Mitzenmacher).
    fn positions(&self, key: &PubKeyBytes) -> impl Iterator<Item = usize> + '_ {
        let d = Sha256::digest(key);
        let h1 = u64::from_be_bytes(d[0..8].try_into().unwrap());
        let h2 = u64::from_be_bytes(d[8..16].try_into().unwrap());
        let num_bits = self.num_bits as u64;
        (0..self.num_hashes)
            .map(move |i| (h1.wrapping_add((i as u64).wrapping_mul(h2)) % num_bits) as usize)
    }

    /// Add a payer to the probabilistic filter.
    pub fn insert(&mut self, key: &PubKeyBytes) {
        let positions: Vec<usize> = self.positions(key).collect();
        for pos in positions {
            self.bits[pos / 8] |= 1 << (pos % 8);
        }
    }

    /// Add a payer to the exact recent-fork set (no false positives).
    pub fn insert_recent(&mut self, key: PubKeyBytes) {
        self.exact_recent.insert(key);
    }

    /// True if the key is definitely in the exact set, or possibly in the filter.
    /// False means definitely not blocked.
    pub fn contains(&self, key: &PubKeyBytes) -> bool {
        if self.exact_recent.contains(key) {
            return true;
        }
        self.positions(key)
            .all(|pos| self.bits[pos / 8] & (1 << (pos % 8)) != 0)
    }

    /// True if the key is in the exact set, with no false-positive possibility.
    pub fn contains_exact(&self, key: &PubKeyBytes) -> bool {
        self.exact_recent.contains(key)
    }

    /// Probabilistic membership only, ignoring the exact set.
    ///
    /// Exposed because publication puts every blocked payer in the filter *as well as*
    /// the exact set, so that the filter alone remains a complete answer; this is how
    /// that invariant is checked.
    pub fn contains_in_filter(&self, key: &PubKeyBytes) -> bool {
        self.positions(key)
            .all(|pos| self.bits[pos / 8] & (1 << (pos % 8)) != 0)
    }

    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    pub fn num_hashes(&self) -> u32 {
        self.num_hashes
    }

    pub fn bits(&self) -> &[u8] {
        &self.bits
    }

    /// The exact set in ascending key order.
    pub fn exact_recent(&self) -> impl Iterator<Item = &PubKeyBytes> {
        self.exact_recent.iter()
    }

    /// Package this filter for publication. The caller signs
    /// [`SignedBlockList::body_digest`] and fills in `sig_issuer`.
    pub fn to_unsigned(&self, epoch: u64, issued_at: u64, not_after: u64) -> SignedBlockList {
        SignedBlockList {
            epoch,
            issued_at,
            not_after,
            num_bits: self.num_bits as u64,
            num_hashes: self.num_hashes as u64,
            bits: self.bits.clone(),
            exact_recent: self.exact_recent.iter().copied().collect(),
            sig_issuer: [0u8; 64],
        }
    }
}

// ---------------------------------------------------------------------------
// SignedBlockList. keys:
// 0=epoch, 1=issued_at, 2=not_after, 3=num_bits, 4=num_hashes,
// 5=bits, 6=exact_recent, 7=sig_issuer
// The signed body is keys 0..=6 (everything except sig_issuer).
// ---------------------------------------------------------------------------

/// An issuer-published block list, ready to distribute and install.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedBlockList {
    /// Monotonic publication counter. An install requires strictly greater than
    /// the epoch already held, which is what prevents a rollback replay.
    pub epoch: u64,
    pub issued_at: u64,
    /// After this UTC second the list is *stale*, not void. See the module docs.
    pub not_after: u64,
    pub num_bits: u64,
    pub num_hashes: u64,
    pub bits: Vec<u8>,
    /// Exact-set keys, strictly ascending (canonical).
    pub exact_recent: Vec<PubKeyBytes>,
    pub sig_issuer: SigBytes,
}

impl SignedBlockList {
    /// Encode the signed body (keys 0..=6).
    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, false);
        e.into_bytes()
    }

    pub fn body_digest(&self) -> Hash {
        Sha256::digest(self.encode_body()).into()
    }

    /// Full encoding including the issuer signature. This is what gets distributed.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, true);
        e.into_bytes()
    }

    fn encode_common(&self, e: &mut Encoder, include_sig: bool) {
        e.map_head(if include_sig { 8 } else { 7 });
        e.map_key(0);
        e.u64(self.epoch);
        e.map_key(1);
        e.u64(self.issued_at);
        e.map_key(2);
        e.u64(self.not_after);
        e.map_key(3);
        e.u64(self.num_bits);
        e.map_key(4);
        e.u64(self.num_hashes);
        e.map_key(5);
        e.bytes(&self.bits);
        e.map_key(6);
        e.array_head(self.exact_recent.len());
        for k in &self.exact_recent {
            e.bytes(k);
        }
        if include_sig {
            e.map_key(7);
            e.bytes(&self.sig_issuer);
        }
    }

    /// Decode a distributed block list. Strict: the shape is validated here, so a
    /// malformed list is an error rather than a panic on a phone.
    pub fn decode(bytes: &[u8]) -> Result<Self, BlockListError> {
        let mut d = Decoder::new(bytes);
        let n = d.map_head()?;
        if n != 8 {
            return Err(BlockListError::Decode(DecodeError::WrongArrayLen));
        }
        let mut last = None;
        let mut epoch = None;
        let mut issued_at = None;
        let mut not_after = None;
        let mut num_bits = None;
        let mut num_hashes = None;
        let mut bits = None;
        let mut exact_recent = None;
        let mut sig = None;
        for _ in 0..8 {
            match d.map_key(&mut last)? {
                0 => epoch = Some(d.u64()?),
                1 => issued_at = Some(d.u64()?),
                2 => not_after = Some(d.u64()?),
                3 => num_bits = Some(d.u64()?),
                4 => num_hashes = Some(d.u64()?),
                5 => bits = Some(d.bytes()?),
                6 => {
                    let count = d.array_head()?;
                    // Checked before the loop so a huge claimed count cannot drive
                    // a large allocation before it fails.
                    if count > MAX_EXACT_RECENT {
                        return Err(BlockListError::TooLarge);
                    }
                    let mut keys = Vec::new();
                    for _ in 0..count {
                        keys.push(d.bytes_fixed::<33>()?);
                    }
                    exact_recent = Some(keys);
                }
                7 => sig = Some(d.bytes_fixed::<64>()?),
                k => return Err(BlockListError::Decode(DecodeError::UnexpectedField(k))),
            }
        }
        d.finish()?;
        let list = SignedBlockList {
            epoch: epoch.ok_or(DecodeError::MissingField(0))?,
            issued_at: issued_at.ok_or(DecodeError::MissingField(1))?,
            not_after: not_after.ok_or(DecodeError::MissingField(2))?,
            num_bits: num_bits.ok_or(DecodeError::MissingField(3))?,
            num_hashes: num_hashes.ok_or(DecodeError::MissingField(4))?,
            bits: bits.ok_or(DecodeError::MissingField(5))?,
            exact_recent: exact_recent.ok_or(DecodeError::MissingField(6))?,
            sig_issuer: sig.ok_or(DecodeError::MissingField(7))?,
        };
        list.check_shape()?;
        Ok(list)
    }

    /// Validate the filter geometry and the exact set's ordering.
    ///
    /// Every check here exists to stop a phone crashing or hanging on a hostile
    /// list: a zero `num_bits` would divide by zero when deriving positions, a
    /// short bit buffer would index out of bounds, and an oversized filter or
    /// probe count is a memory or CPU exhaustion vector.
    fn check_shape(&self) -> Result<(), BlockListError> {
        if self.num_bits < 8 || self.num_hashes == 0 {
            return Err(BlockListError::BadGeometry);
        }
        if self.num_bits > (MAX_FILTER_BYTES as u64) * 8 || self.num_hashes > MAX_HASHES as u64 {
            return Err(BlockListError::TooLarge);
        }
        // Safe to narrow: the bound above keeps num_bits inside u32, so this holds
        // on a 32-bit target too.
        let expected = (self.num_bits as usize).div_ceil(8);
        if self.bits.len() != expected {
            return Err(BlockListError::BadGeometry);
        }
        if self.exact_recent.len() > MAX_EXACT_RECENT {
            return Err(BlockListError::TooLarge);
        }
        for w in self.exact_recent.windows(2) {
            if w[0] >= w[1] {
                return Err(BlockListError::ExactSetNotSorted);
            }
        }
        Ok(())
    }

    /// Verify this list against the issuer key and open it for use.
    ///
    /// `current_epoch` is the epoch of the list the device already holds, or `None`
    /// on first install. The offered epoch must be strictly greater.
    ///
    /// Deliberately takes no clock. An expired list still installs and still
    /// blocks, because refusing it would leave the device holding an *older* list
    /// that blocks fewer cheaters — the wrong direction to fail. Staleness is
    /// reported by [`InstalledBlockList::is_stale`] and should tighten the payee's
    /// offline limits instead.
    ///
    /// Shape is checked before the signature so a structurally impossible list
    /// costs no elliptic-curve work on a slow device.
    pub fn verify_and_open<V: Verifier>(
        &self,
        issuer_pubkey: &PubKeyBytes,
        verifier: &V,
        current_epoch: Option<u64>,
    ) -> Result<InstalledBlockList, BlockListError> {
        if self.not_after < self.issued_at {
            return Err(BlockListError::InvertedWindow);
        }
        self.check_shape()?;

        verifier
            .verify_prehash(issuer_pubkey, &self.body_digest(), &self.sig_issuer)
            .map_err(|e| match e {
                CryptoError::HighS => BlockListError::MalleableSignature,
                _ => BlockListError::BadIssuerSignature,
            })?;

        if let Some(current) = current_epoch {
            if self.epoch <= current {
                return Err(BlockListError::StaleEpoch {
                    current,
                    offered: self.epoch,
                });
            }
        }

        let mut list = BlockList::new(self.num_bits as usize, self.num_hashes as u32);
        list.bits.copy_from_slice(&self.bits);
        for k in &self.exact_recent {
            list.insert_recent(*k);
        }

        Ok(InstalledBlockList {
            epoch: self.epoch,
            issued_at: self.issued_at,
            not_after: self.not_after,
            list,
        })
    }
}

/// A verified block list held on a device. The platform persists this (or at least
/// its `epoch`) so the next install can be checked for rollback.
#[derive(Debug, Clone)]
pub struct InstalledBlockList {
    epoch: u64,
    issued_at: u64,
    not_after: u64,
    list: BlockList,
}

impl InstalledBlockList {
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }

    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Is this payer blocked? False means definitely not blocked; true means
    /// definitely blocked if [`contains_exact`](Self::contains_exact) also holds,
    /// and otherwise carries the filter's false-positive probability.
    pub fn contains(&self, key: &PubKeyBytes) -> bool {
        self.list.contains(key)
    }

    /// Is this payer in the exact set, with no false-positive possibility?
    pub fn contains_exact(&self, key: &PubKeyBytes) -> bool {
        self.list.contains_exact(key)
    }

    /// Probabilistic membership only, ignoring the exact set.
    pub fn contains_in_filter(&self, key: &PubKeyBytes) -> bool {
        self.list.contains_in_filter(key)
    }

    /// Past `not_after`. Advisory: entries stay in force, but the *absence* of an
    /// entry is now less meaningful, so a payee should lower its offline limits
    /// rather than treat the list as void.
    pub fn is_stale(&self, now: u64) -> bool {
        now > self.not_after
    }

    pub fn list(&self) -> &BlockList {
        &self.list
    }

    /// Number of exact-set entries.
    pub fn exact_count(&self) -> usize {
        self.list.exact_recent().count()
    }

    /// Take ownership of the filter, so a caller can merge additional locally-known
    /// blocked keys into it before using it to verify a promise.
    pub fn into_list(self) -> BlockList {
        self.list
    }
}
