//! Checkpoints (B7): making the **issuer** unable to equivocate.
//!
//! The protocol already makes a payer unable to lie: two promises at the same `seq` are
//! a [`crate::ForkProof`], signed by the payer's own hardware, that anybody can check.
//! The issuer had no equivalent. It signs the block list, so it could:
//!
//! * publish one list to some devices and a *different* list at the same `epoch` to
//!   others — the epoch rule stops one device installing both, but nothing stops the
//!   issuer telling two devices different stories;
//! * quietly rewrite what it published last week, since a device that has moved on keeps
//!   no evidence of the list it replaced.
//!
//! A checkpoint closes that. Every publication gets one [`Checkpoint`]: its position in
//! the issuer's log, the epoch and body digest of the list it commits to, and a hash link
//! to the entry before it. Signed, so it is the issuer's own word, and chained, so a
//! history cannot be rewritten without breaking every later link.
//!
//! **This is B2 turned on the issuer.** The payer is chained by `(seq, prev_hash)` and
//! forks by reusing a `seq`; the issuer is now chained by `(seq, prev_hash)` and
//! equivocates by reusing one. Two checkpoints that cannot both belong to one honest log
//! are an [`EquivocationProof`] — the issuer's analogue of a fork proof, and just as
//! portable, just as independently checkable, and just as free of anyone's say-so.
//!
//! ## Why the log position is separate from the list epoch
//!
//! `seq` counts checkpoints; `epoch` counts published block lists. They advance together
//! but are not the same number, and conflating them costs real detection power.
//!
//! The log owns `seq` and appends consecutively, so `seq` can never gain a gap. That is
//! what makes the strongest rule below (E2) sound: a successor at `seq n+1` must name the
//! *unique* entry at `seq n`, so a successor naming anything else is proof that two
//! entries exist at one position. `epoch` cannot carry that rule, because it comes from
//! outside — a service that increments its publication counter and then fails mid-publish
//! leaves a legitimate gap, and a rule that treated gaps as fraud would convict an honest
//! issuer for crashing.
//!
//! ## What this does and does not buy
//!
//! Being precise here matters, because the guarantee is narrower than it first looks.
//!
//! A checkpoint chain makes equivocation **provable once two views are compared**. It
//! does not by itself make the comparison happen: two devices that never meet, and never
//! read a common source, can be told different histories indefinitely. That is why
//! anchoring the head to somewhere public is the other half of B7
//! (`igopay_issuer::anchor`) — a single place everyone reads is what turns "detectable in
//! principle" into "detected in practice". This is the Certificate Transparency shape: a
//! log makes misbehaviour undeniable, and gossip or witnesses make it visible.
//!
//! What it does buy immediately, with no anchor at all: a device keeps the checkpoints it
//! has seen, and any two devices that *do* compare — at a market, through a carried
//! bundle (B12), in a dispute — produce evidence rather than two conflicting stories.
//!
//! It also buys something on the issuer's own side, which is easy to miss: an
//! append-only log that refuses a non-advancing epoch makes same-epoch equivocation
//! impossible **by accident**. Before this, two racing publisher processes could ship two
//! epoch-9 lists without anyone noticing. Now that is a refused append.
//!
//! Note what a checkpoint deliberately does **not** prove: that the list's *contents* are
//! correct. An issuer that omits a real cheat, or lists an innocent payer, is equivocating
//! about nothing — it publishes one consistent history that happens to be wrong. Catching
//! that needs the fork proofs themselves, which any payee can already verify
//! independently. Checkpoints constrain the issuer to **one** story; they cannot make that
//! story true.

use crate::blocklist::{BlockListError, InstalledBlockList, SignedBlockList};
use crate::codec::{Decoder, Encoder};
use crate::crypto::{CryptoError, PubKeyBytes, SigBytes, Verifier};
use crate::types::{DecodeError, Hash};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// The `prev_hash` of the checkpoint at `seq = 0`, and only that one.
///
/// Enforced in both directions ([`verify_checkpoint`]): `seq == 0` must carry it and
/// `seq > 0` must not, so "this is the start of the log" is never ambiguous.
pub const GENESIS_PREV: Hash = [0u8; 32];

/// Why a checkpoint, a chain link, or a claimed proof was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointError {
    Decode(DecodeError),
    /// Not signed by the expected issuer key.
    BadIssuerSignature,
    /// The signature was well-formed but high-S. Rejected everywhere in this protocol
    /// (see [`crate::crypto`]) — and here especially, because a malleated copy of an
    /// honest checkpoint would otherwise masquerade as evidence of equivocation.
    MalleableSignature,
    /// `seq == 0` without [`GENESIS_PREV`], or `seq > 0` with it.
    BadGenesis,
    /// The successor's `seq` is not exactly one past its predecessor's.
    PositionNotAdjacent {
        prev: u64,
        next: u64,
    },
    /// `prev_hash` does not match the digest of the checkpoint it claims to follow.
    ChainBroken {
        expected: Hash,
        got: Hash,
    },
    /// The successor's epoch is not strictly greater than its predecessor's.
    EpochNotAdvancing {
        prev: u64,
        next: u64,
    },
    /// The checkpoint does not commit to the block list it was delivered with — wrong
    /// epoch, or the right epoch with a different body.
    ListNotCommitted,
    /// The block list itself was refused; the checkpoint is not the problem.
    List(BlockListError),
    /// A witnessed checkpoint's cosignatures were not strictly ascending by witness key —
    /// non-canonical ordering, or the same witness repeated to inflate the apparent
    /// coverage.
    CosignaturesNotSorted,
    /// A cosignature names a different checkpoint than the one it arrived attached to.
    CosignatureForAnotherCheckpoint,
    /// A cosignature attests to a *different issuer's* history. Two issuers publishing the
    /// same list at the same position produce identical checkpoint bodies, so a cosignature
    /// names the issuer as well as the digest; see [`crate::witness::Cosignature`].
    CosignatureForAnotherIssuer,
    /// A cosignature from a **trusted** witness did not verify. Not ignorable: it means
    /// either the artefact was tampered with or that witness key is compromised.
    BadWitnessSignature,
    /// A claimed equivocation proof does not prove equivocation: the two checkpoints can
    /// both belong to one honest log, or one of them is not validly signed.
    NotEquivocation,
}

impl From<DecodeError> for CheckpointError {
    fn from(e: DecodeError) -> Self {
        CheckpointError::Decode(e)
    }
}

impl From<crate::codec::CodecError> for CheckpointError {
    fn from(e: crate::codec::CodecError) -> Self {
        CheckpointError::Decode(DecodeError::Codec(e))
    }
}

impl From<BlockListError> for CheckpointError {
    fn from(e: BlockListError) -> Self {
        CheckpointError::List(e)
    }
}

fn map_crypto_err(e: CryptoError) -> CheckpointError {
    match e {
        CryptoError::HighS => CheckpointError::MalleableSignature,
        _ => CheckpointError::BadIssuerSignature,
    }
}

// ---------------------------------------------------------------------------
// Checkpoint. keys:
// 0=seq, 1=epoch, 2=list_digest, 3=prev_hash, 4=issued_at, 5=sig_issuer
// The signed body is keys 0..=4 (everything except sig_issuer).
// ---------------------------------------------------------------------------

/// One entry in the issuer's published history: "at this position, the block list was
/// exactly this, at exactly this epoch, and it followed exactly that."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// Position in the issuer's log, from 0, with no gaps. See the module docs for why
    /// this is not the list epoch.
    pub seq: u64,
    /// The epoch of the block list this checkpoint commits to.
    pub epoch: u64,
    /// [`SignedBlockList::body_digest`] of the published list.
    ///
    /// The *body* digest, not a hash of the full artefact, so list identity is its
    /// content — the same reasoning as promise identity for fork detection. A re-signed
    /// but otherwise identical list is the same list and must not look like equivocation.
    pub list_digest: Hash,
    /// [`Checkpoint::body_digest`] of the entry at `seq - 1`, or [`GENESIS_PREV`] at
    /// `seq == 0`.
    pub prev_hash: Hash,
    /// The issuer's own publication time. Advisory: it is the issuer's clock, so it is
    /// not evidence of anything and no rule here depends on it.
    pub issued_at: u64,
    pub sig_issuer: SigBytes,
}

impl Checkpoint {
    fn encode_common(&self, e: &mut Encoder, include_sig: bool) {
        e.map_head(if include_sig { 6 } else { 5 });
        e.map_key(0);
        e.u64(self.seq);
        e.map_key(1);
        e.u64(self.epoch);
        e.map_key(2);
        e.bytes(&self.list_digest);
        e.map_key(3);
        e.bytes(&self.prev_hash);
        e.map_key(4);
        e.u64(self.issued_at);
        if include_sig {
            e.map_key(5);
            e.bytes(&self.sig_issuer);
        }
    }

    /// Encode the signed body (keys 0..=4).
    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, false);
        e.into_bytes()
    }

    /// The checkpoint's identity, and what its successor's `prev_hash` must equal.
    pub fn body_digest(&self) -> Hash {
        Sha256::digest(self.encode_body()).into()
    }

    /// Full encoding including the issuer signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, true);
        e.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let cp = Self::decode(&mut d)?;
        d.finish()?;
        Ok(cp)
    }

    pub(crate) fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 6 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut seq = None;
        let mut epoch = None;
        let mut list_digest = None;
        let mut prev_hash = None;
        let mut issued_at = None;
        let mut sig = None;
        for _ in 0..6 {
            match d.map_key(&mut last)? {
                0 => seq = Some(d.u64()?),
                1 => epoch = Some(d.u64()?),
                2 => list_digest = Some(d.bytes_fixed::<32>()?),
                3 => prev_hash = Some(d.bytes_fixed::<32>()?),
                4 => issued_at = Some(d.u64()?),
                5 => sig = Some(d.bytes_fixed::<64>()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(Checkpoint {
            seq: seq.ok_or(DecodeError::MissingField(0))?,
            epoch: epoch.ok_or(DecodeError::MissingField(1))?,
            list_digest: list_digest.ok_or(DecodeError::MissingField(2))?,
            prev_hash: prev_hash.ok_or(DecodeError::MissingField(3))?,
            issued_at: issued_at.ok_or(DecodeError::MissingField(4))?,
            sig_issuer: sig.ok_or(DecodeError::MissingField(5))?,
        })
    }

    /// Is this the first entry in the log?
    pub fn is_genesis(&self) -> bool {
        self.seq == 0
    }

    /// Structural well-formedness, independent of any signature: the genesis marker must
    /// agree with the position. Checked before the signature so a nonsense checkpoint
    /// costs no elliptic-curve work on a slow device.
    fn check_wellformed(&self) -> Result<(), CheckpointError> {
        let genesis_marked = self.prev_hash == GENESIS_PREV;
        if genesis_marked != (self.seq == 0) {
            return Err(CheckpointError::BadGenesis);
        }
        Ok(())
    }
}

/// Verify a checkpoint: well-formed, and signed by the issuer.
pub fn verify_checkpoint<V: Verifier>(
    checkpoint: &Checkpoint,
    issuer_pubkey: &PubKeyBytes,
    verifier: &V,
) -> Result<(), CheckpointError> {
    checkpoint.check_wellformed()?;
    verifier
        .verify_prehash(
            issuer_pubkey,
            &checkpoint.body_digest(),
            &checkpoint.sig_issuer,
        )
        .map_err(map_crypto_err)
}

/// Verify that `next` legitimately follows `prev`: both signed by the issuer, the
/// position advances by exactly one, the hash link holds, and the epoch advances.
///
/// This is what closes a gap once the missing links are fetched, and what an auditor runs
/// over a whole log.
pub fn verify_chain_link<V: Verifier>(
    prev: &Checkpoint,
    next: &Checkpoint,
    issuer_pubkey: &PubKeyBytes,
    verifier: &V,
) -> Result<(), CheckpointError> {
    verify_checkpoint(prev, issuer_pubkey, verifier)?;
    verify_checkpoint(next, issuer_pubkey, verifier)?;
    if next.seq != prev.seq.saturating_add(1) {
        return Err(CheckpointError::PositionNotAdjacent {
            prev: prev.seq,
            next: next.seq,
        });
    }
    if next.epoch <= prev.epoch {
        return Err(CheckpointError::EpochNotAdvancing {
            prev: prev.epoch,
            next: next.epoch,
        });
    }
    let expected = prev.body_digest();
    if next.prev_hash != expected {
        return Err(CheckpointError::ChainBroken {
            expected,
            got: next.prev_hash,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binding a checkpoint to the list it commits to.
// ---------------------------------------------------------------------------

/// Does this checkpoint commit to this block list?
///
/// Without this check the chain is decorative. An issuer could publish one checkpoint
/// chain that every device agrees on, and separately hand one device an *uncheckpointed*
/// list — leaving that device with no evidence of what it was told. Requiring a
/// commitment is what forces a divergent list to come with a divergent checkpoint, and a
/// divergent checkpoint is the proof. (Certificate Transparency does the same thing by
/// refusing a certificate that arrives without an SCT.)
pub fn verify_list_commitment(
    list: &SignedBlockList,
    checkpoint: &Checkpoint,
) -> Result<(), CheckpointError> {
    if checkpoint.epoch != list.epoch || checkpoint.list_digest != list.body_digest() {
        return Err(CheckpointError::ListNotCommitted);
    }
    Ok(())
}

/// Install a block list together with the checkpoint that commits to it.
///
/// The device-side install path for B7: verify the checkpoint, verify that it commits to
/// this exact list, then apply every block-list install rule
/// ([`SignedBlockList::verify_and_open`]) unchanged. The caller still has to offer the
/// checkpoint to its [`CheckpointTracker`] — that is what turns the copy it just
/// installed into evidence it can compare later.
///
/// Note the order: the checkpoint is verified first, so a list that arrives with a
/// checkpoint the issuer never signed is refused before any list state changes.
pub fn install_checkpointed_list<V: Verifier>(
    list: &SignedBlockList,
    checkpoint: &Checkpoint,
    issuer_pubkey: &PubKeyBytes,
    verifier: &V,
    current_epoch: Option<u64>,
) -> Result<InstalledBlockList, CheckpointError> {
    verify_checkpoint(checkpoint, issuer_pubkey, verifier)?;
    verify_list_commitment(list, checkpoint)?;
    let installed = list.verify_and_open(issuer_pubkey, verifier, current_epoch)?;
    Ok(installed)
}

// ---------------------------------------------------------------------------
// EquivocationProof: two checkpoints that cannot both be in one honest log.
// Encoded as a 2-element array [checkpoint_a, checkpoint_b], mirroring ForkProof.
// ---------------------------------------------------------------------------

/// Which rule a pair of checkpoints breaks. Always *derived* from the pair, never carried
/// in the wire format — a claimed reason is worth nothing, and re-deriving it costs two
/// comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EquivocationKind {
    /// **E1.** Two different entries at one log position. The direct analogue of a payer
    /// reusing a `seq`, and what "two block lists at one epoch" collapses to when the
    /// issuer reuses the position as well.
    DuplicatePosition,
    /// **E2.** A successor that does not name the entry it must follow. The log appends
    /// consecutively, so the entry at `seq n+1` names the *unique* entry at `seq n`; one
    /// that names anything else says there are two entries at `n`. This is the rule that
    /// catches a rewrite of last week's history, and a chain quietly split in two.
    BrokenLink,
    /// **E3.** Epoch and position not co-monotone: a later entry with an epoch that did
    /// not advance. This is what catches "two different lists at the same epoch" when the
    /// issuer is careful enough to put them at different positions, and it catches an
    /// epoch rollback.
    EpochNotAdvancing,
}

/// Evidence that the issuer's published history is not one history.
///
/// Deliberately the same shape as [`crate::ForkProof`]: two signed artefacts that cannot
/// both be honest. A payer who forks is caught by their own signatures; an issuer who
/// equivocates is caught by its own signatures. Neither needs a trusted party to
/// adjudicate, which is the property that lets this system be audited by the people it
/// affects rather than only by whoever runs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquivocationProof {
    pub a: Checkpoint,
    pub b: Checkpoint,
}

impl EquivocationProof {
    /// Order the pair canonically, by `(seq, body_digest)`.
    ///
    /// Ordering is for deduplication, not security: the same equivocation found by two
    /// different devices then encodes to the same bytes, so an issuer cannot be reported
    /// twice for one offence and a store can key on the artefact. Nothing about what is
    /// proven depends on the order, which is why [`Self::from_bytes`] accepts either.
    pub fn new(a: Checkpoint, b: Checkpoint) -> Self {
        let swap = (b.seq, b.body_digest()) < (a.seq, a.body_digest());
        if swap {
            EquivocationProof { a: b, b: a }
        } else {
            EquivocationProof { a, b }
        }
    }

    /// Which rule this pair breaks, or `None` if it breaks none (the pair is innocent).
    /// Order-independent.
    pub fn kind(&self) -> Option<EquivocationKind> {
        equivocation_kind(&self.a, &self.b)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array_head(2);
        // Each checkpoint's own encoding is already canonical; append verbatim.
        e.raw(&self.a.encode());
        e.raw(&self.b.encode());
        e.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let n = d.array_head()?;
        if n != 2 {
            return Err(DecodeError::WrongArrayLen);
        }
        let a = Checkpoint::decode(&mut d)?;
        let b = Checkpoint::decode(&mut d)?;
        d.finish()?;
        Ok(EquivocationProof { a, b })
    }
}

/// The rule a pair of checkpoints breaks, if any. Structural only — signatures are not
/// consulted here (see [`detect_equivocation`]).
fn equivocation_kind(a: &Checkpoint, b: &Checkpoint) -> Option<EquivocationKind> {
    // E1: same position, different content.
    if a.seq == b.seq {
        return if a.body_digest() == b.body_digest() {
            None
        } else {
            Some(EquivocationKind::DuplicatePosition)
        };
    }

    // Orient: `lo` is the earlier position.
    let (lo, hi) = if a.seq < b.seq { (a, b) } else { (b, a) };

    // E3: position advanced, epoch did not.
    if hi.epoch <= lo.epoch {
        return Some(EquivocationKind::EpochNotAdvancing);
    }

    // E2: adjacent positions whose hash link does not hold. Only checkable when the two
    // are adjacent; a wider gap needs the intervening entries, which is exactly why
    // devices retain a window and why the head gets anchored.
    if hi.seq == lo.seq + 1 && hi.prev_hash != lo.body_digest() {
        return Some(EquivocationKind::BrokenLink);
    }

    None
}

/// Attempt to construct an equivocation proof from two checkpoints.
///
/// Returns `None` when the pair can honestly coexist — including the ordinary cases of
/// the same checkpoint seen twice, and two entries far enough apart that nothing links
/// them.
///
/// Signature checking is NOT done here, exactly as [`crate::detect_fork`] does not: this
/// is the cheap structural test, and [`verify_equivocation_proof`] is what a third party
/// runs before acting. Callers that hold unverified checkpoints must verify them first —
/// [`CheckpointTracker::offer`] does.
pub fn detect_equivocation(a: &Checkpoint, b: &Checkpoint) -> Option<EquivocationProof> {
    equivocation_kind(a, b)?;
    Some(EquivocationProof::new(a.clone(), b.clone()))
}

/// Independently verify a claimed equivocation proof: the pair breaks a rule, and BOTH
/// signatures are valid under the issuer's key. Returns which rule it breaks.
///
/// A fabricated pair — including one built by malleating an honest checkpoint's
/// signature — must not convict an honest issuer, which is why high-S is refused here
/// too.
pub fn verify_equivocation_proof<V: Verifier>(
    proof: &EquivocationProof,
    issuer_pubkey: &PubKeyBytes,
    verifier: &V,
) -> Result<EquivocationKind, CheckpointError> {
    let kind = proof.kind().ok_or(CheckpointError::NotEquivocation)?;
    verify_checkpoint(&proof.a, issuer_pubkey, verifier)?;
    verify_checkpoint(&proof.b, issuer_pubkey, verifier)?;
    Ok(kind)
}

// ---------------------------------------------------------------------------
// Device-side: what a phone does with a checkpoint it is handed.
// ---------------------------------------------------------------------------

/// What an offered checkpoint turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointVerdict {
    /// Nothing was held for this issuer, so there was nothing to compare against and
    /// nothing is proven either way. Retained; the comparisons start from here.
    FirstSeen,
    /// Extends the head by exactly one position, hash link intact.
    Advanced,
    /// Installed, but positions were skipped, so continuity across them is unproven.
    ///
    /// This is the normal shape of a device that was offline for a month: block lists are
    /// whole snapshots, not increments, so it installs the newest and never sees the
    /// intermediate ones. Fetching the missing checkpoints (from the issuer, or from
    /// another device carrying them) closes the gap with [`verify_chain_link`].
    ///
    /// Accepted rather than refused on purpose. Refusing would leave the device on an
    /// older block list that blocks *fewer* cheaters — the same "never fail open on
    /// revocation" reasoning as block-list staleness (`crate::blocklist`).
    AdvancedWithGap { skipped: u64 },
    /// Byte-identical in content to one already held: a re-delivery, not an event.
    Duplicate,
    /// An earlier position than the head, compatible with everything held. Retained if
    /// there is room, because an older entry is extra comparison surface against a later
    /// rewrite; it does not move the head.
    Superseded { head: u64, offered: u64 },
    /// The offered checkpoint cannot coexist with one already held: the issuer
    /// equivocated. Carries the portable proof.
    ///
    /// Boxed because the proof is two whole checkpoints while the other verdicts are a
    /// couple of words, and this is the rare path on a call every device makes routinely.
    Equivocation(Box<EquivocationProof>),
}

/// Classify `offered` against the checkpoints already held, in evidence-first order.
///
/// Pure and stateless, so the FFI can expose it to a platform that persists the retained
/// checkpoints itself. Every element of `held` **must** already have been verified
/// against the issuer key, and so must `offered`; this function only compares. Feeding it
/// unverified input would manufacture verdicts from bytes nobody signed.
///
/// The equivocation pass doubles as the continuity check, which is why [`Advanced`] can
/// be returned without a separate link test: if the offered checkpoint sat one past the
/// head with a broken link, E2 would already have fired.
///
/// [`Advanced`]: CheckpointVerdict::Advanced
pub fn classify_checkpoint(held: &[&Checkpoint], offered: &Checkpoint) -> CheckpointVerdict {
    // Evidence first. A checkpoint that convicts the issuer must never be filed away as
    // an ordinary update just because it also happens to look like one.
    for h in held {
        if let Some(proof) = detect_equivocation(h, offered) {
            return CheckpointVerdict::Equivocation(Box::new(proof));
        }
    }

    let offered_digest = offered.body_digest();
    if held.iter().any(|h| h.body_digest() == offered_digest) {
        return CheckpointVerdict::Duplicate;
    }

    match held.iter().max_by_key(|c| c.seq) {
        None => CheckpointVerdict::FirstSeen,
        Some(head) => {
            if offered.seq == head.seq.saturating_add(1) {
                CheckpointVerdict::Advanced
            } else if offered.seq > head.seq {
                CheckpointVerdict::AdvancedWithGap {
                    skipped: offered.seq - head.seq - 1,
                }
            } else {
                CheckpointVerdict::Superseded {
                    head: head.seq,
                    offered: offered.seq,
                }
            }
        }
    }
}

/// The checkpoints a device holds for one issuer, and the comparison that turns a second
/// story into a proof.
///
/// Shaped like [`crate::PayeeLedger`], for the same reason: the core does no I/O, so this
/// is an in-memory model of what the app persists, and it is **bounded** because the
/// target device is Android Go with `ram.low` (`research/09` §3). A checkpoint is about
/// 180 bytes, so a window of a few dozen is nothing — but "a few dozen" is a decision,
/// not an accident.
///
/// ## Why keep more than the head
///
/// The head alone catches an issuer that hands two devices different current lists. It
/// cannot catch a *rewrite*: a device that has moved on to position 40 holds nothing to
/// compare against a re-signed position 12. A retained window is what lets the comparison
/// succeed at a position both devices still remember, and it is the only reason E2 (a
/// broken link) is ever reachable in practice.
///
/// Eviction drops the **lowest** `seq`, keeping the window near the head where devices
/// are most likely to overlap. Evicting is a deliberate, documented loss of evidence:
/// beyond the window, detecting a rewrite is the anchor's job, not the phone's.
#[derive(Debug, Clone)]
pub struct CheckpointTracker {
    issuer_pubkey: PubKeyBytes,
    retained: BTreeMap<u64, Checkpoint>,
    retain: usize,
}

impl CheckpointTracker {
    /// Track `issuer_pubkey`, retaining at most `retain` checkpoints (clamped to at least
    /// 1, since retaining none would silently disable every comparison this type exists
    /// to make).
    pub fn new(issuer_pubkey: PubKeyBytes, retain: usize) -> Self {
        CheckpointTracker {
            issuer_pubkey,
            retained: BTreeMap::new(),
            retain: retain.max(1),
        }
    }

    /// Track `issuer_pubkey`, retaining **everything**.
    ///
    /// For a party whose whole job is remembering: a witness ([`crate::witness::WitnessLog`])
    /// that forgot a position could be talked into cosigning a second checkpoint there, which
    /// is precisely the thing it exists to refuse. A phone should not do this; the cost is
    /// about 180 bytes per publication, which is nothing for a server and still only ~1.5 MB
    /// a year at hourly publication.
    pub fn retaining_all(issuer_pubkey: PubKeyBytes) -> Self {
        CheckpointTracker::new(issuer_pubkey, usize::MAX)
    }

    /// Offer a checkpoint the device just received.
    ///
    /// Verifies it against the issuer key first — an unsigned or misattributed checkpoint
    /// is an error, never a verdict — then classifies it against everything retained, and
    /// only then updates state.
    ///
    /// On [`CheckpointVerdict::Equivocation`] **nothing is retained**. The device keeps
    /// the view it already had and hands the proof to the caller; adopting the second
    /// story would destroy the evidence for the first, which is precisely what an
    /// equivocating issuer wants.
    pub fn offer<V: Verifier>(
        &mut self,
        offered: &Checkpoint,
        verifier: &V,
    ) -> Result<CheckpointVerdict, CheckpointError> {
        verify_checkpoint(offered, &self.issuer_pubkey, verifier)?;

        let held: Vec<&Checkpoint> = self.retained.values().collect();
        let verdict = classify_checkpoint(&held, offered);

        match verdict {
            CheckpointVerdict::Equivocation(_) | CheckpointVerdict::Duplicate => {}
            _ => self.retain_checkpoint(offered.clone()),
        }
        Ok(verdict)
    }

    fn retain_checkpoint(&mut self, cp: Checkpoint) {
        self.retained.insert(cp.seq, cp);
        while self.retained.len() > self.retain {
            let lowest = match self.retained.keys().next() {
                Some(&k) => k,
                None => break,
            };
            self.retained.remove(&lowest);
        }
    }

    /// The highest-position checkpoint held: the device's current view of the issuer's
    /// history.
    pub fn head(&self) -> Option<&Checkpoint> {
        self.retained.values().next_back()
    }

    /// The retained checkpoint at `seq`, if it has not been evicted.
    pub fn at(&self, seq: u64) -> Option<&Checkpoint> {
        self.retained.get(&seq)
    }

    /// The identity of the current head, for comparing against a digest read from
    /// somewhere public.
    pub fn head_digest(&self) -> Option<Hash> {
        self.head().map(|cp| cp.body_digest())
    }

    /// Where a checkpoint digest sits in this device's retained history.
    ///
    /// The device's half of the anchor check (`igopay_issuer::anchor`): read the head digest
    /// the issuer published somewhere public, and ask whether it is part of the history
    /// *this* phone was told. The answers are not equally informative and must not be
    /// collapsed into a boolean:
    ///
    /// * `Some(seq)` — the public history and this device's history agree at that position.
    ///   This is the assurance the anchor exists to give.
    /// * `None`, for a digest older than the retained window — unknowable here, not an
    ///   alarm. Bounded storage is a deliberate choice with this exact cost.
    /// * `None`, where the window should have covered it — this device is on a different
    ///   chain from the public one. The alarm, and the reason to go and fetch the
    ///   checkpoint behind that digest: holding it turns a mismatch into a proof.
    pub fn position_of(&self, digest: &Hash) -> Option<u64> {
        self.retained
            .values()
            .find(|cp| &cp.body_digest() == digest)
            .map(|cp| cp.seq)
    }

    /// Retained checkpoints in ascending position order.
    pub fn retained(&self) -> impl Iterator<Item = &Checkpoint> {
        self.retained.values()
    }

    pub fn len(&self) -> usize {
        self.retained.len()
    }

    pub fn is_empty(&self) -> bool {
        self.retained.is_empty()
    }

    /// The issuer this tracker is pinned to.
    pub fn issuer_pubkey(&self) -> &PubKeyBytes {
        &self.issuer_pubkey
    }

    /// Does the block list the device is about to install match a checkpoint it holds?
    ///
    /// The install path ([`install_checkpointed_list`]) already binds a list to *a*
    /// checkpoint. This answers the sharper question — is that checkpoint the one this
    /// device's own history contains — and it is what a payee should ask before treating
    /// a freshly carried list as authoritative.
    pub fn commits_to(&self, list: &SignedBlockList) -> bool {
        let digest = list.body_digest();
        self.retained
            .values()
            .any(|cp| cp.epoch == list.epoch && cp.list_digest == digest)
    }
}
