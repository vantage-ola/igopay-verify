//! Payee-side ledger: the state a payee must persist between payments, and the
//! cross-payment fork detection it enables.
//!
//! ## Why this exists
//!
//! `verify_promise` is stateless — it takes a `known_head` and returns a `new_head`,
//! but something has to *hold* that head between payments, per payer. And there is a
//! sharper reason than bookkeeping: a payer who reuses a `seq` with a different body
//! has double spent, and the two promises together are undeniable evidence
//! ([`crate::ForkProof`]). If the payee keeps only the head digest, it can *reject*
//! the second promise but cannot *prove* anything — the earlier promise is gone.
//!
//! So the ledger keeps two things per payer:
//!   * the [`ChainHead`] — `(seq, body_digest)` of the last accepted promise, fed
//!     back into the next verification to enforce chain continuity (B2);
//!   * a bounded set of **retained promises**, so that when a same-`seq`
//!     different-body promise arrives, [`PayeeLedger::check_for_fork`] can produce a
//!     real fork proof on the spot.
//!
//! ## Bounded by design (the memory constraint is real)
//!
//! The target device is Android **Go edition** with `ram.low` set (`research/09` §3),
//! so unbounded retention is not an option. Retention is capped per payer
//! (`retain_per_payer`); when the cap is hit the **lowest** `seq` is evicted, because
//! recent promises are the ones a double spend is most likely to collide with and the
//! ones a payee can still act on. Eviction is a deliberate, documented loss of
//! evidence, not an oversight — see "What this cannot do".
//!
//! ## What this cannot do (B9, honestly stated)
//!
//! A payee can only detect forks among promises **it has seen**. A payer who spends
//! `seq = 12` with payee A and a different `seq = 12` with payee B is invisible to
//! each of them individually; the fork surfaces only when those two promises are
//! combined (at the issuer, or via a shared block list). This ledger closes the
//! single-payee case and nothing more. It is also *not* a settlement record — an
//! accepted promise is "pending, not settled".

use crate::crypto::PubKeyBytes;
use crate::types::{ForkProof, Promise};
use crate::verify::{Accepted, ChainHead};
use alloc::collections::BTreeMap;

/// What a payee knows about one payer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayerRecord {
    /// The chain head to feed into the next verification for this payer.
    pub head: ChainHead,
    /// Retained promises by `seq`, bounded by the ledger's `retain_per_payer`.
    /// Kept whole (not just digests) because a fork proof needs the full signed
    /// promise, signature included.
    retained: BTreeMap<u64, Promise>,
}

impl PayerRecord {
    /// The retained promise at `seq`, if still held.
    pub fn promise_at(&self, seq: u64) -> Option<&Promise> {
        self.retained.get(&seq)
    }

    /// How many promises are currently retained for this payer.
    pub fn retained_len(&self) -> usize {
        self.retained.len()
    }
}

/// The payee's persistent view across all payers it has transacted with.
///
/// This is an in-memory model of what the app must persist (encrypted, on device).
/// The core does not do I/O: the platform is responsible for saving and restoring
/// it. The types are deliberately simple — a payer key, a head, and encoded
/// promises — so the storage layer has an easy job.
#[derive(Debug, Clone)]
pub struct PayeeLedger {
    payers: BTreeMap<PubKeyBytes, PayerRecord>,
    retain_per_payer: usize,
}

impl PayeeLedger {
    /// Create an empty ledger retaining at most `retain_per_payer` promises per payer
    /// (clamped to at least 1, since retaining zero would make fork detection
    /// impossible and silently defeat the point of the ledger).
    pub fn new(retain_per_payer: usize) -> Self {
        PayeeLedger {
            payers: BTreeMap::new(),
            retain_per_payer: retain_per_payer.max(1),
        }
    }

    /// The chain head for `payer`, to pass as `known_head` on the next verification.
    /// `None` means this payee has never accepted a promise from this payer, and the
    /// continuity checks are simply not asserted (a first-contact payment).
    pub fn head_for(&self, payer: &PubKeyBytes) -> Option<ChainHead> {
        self.payers.get(payer).map(|r| r.head)
    }

    /// The full record for `payer`, if known.
    pub fn record_for(&self, payer: &PubKeyBytes) -> Option<&PayerRecord> {
        self.payers.get(payer)
    }

    /// Number of distinct payers tracked.
    pub fn payer_count(&self) -> usize {
        self.payers.len()
    }

    /// Check an incoming promise against what is already retained for its payer.
    ///
    /// Returns a [`ForkProof`] iff a retained promise has the **same `seq`** but a
    /// **different signed body** — a double spend by that payer. Returns `None` for a
    /// new `seq`, for an exact duplicate (a re-scan, not a fork), or for an unknown
    /// payer.
    ///
    /// Call this BEFORE verification: the returned proof is worth capturing whether
    /// or not the new promise would otherwise be accepted, and verification will
    /// reject the promise anyway (`SeqDiscontinuity`) once a head exists.
    ///
    /// The proof is structural — same payer, same seq, different bodies. Both
    /// promises carry the payer's own signature, so
    /// [`crate::verify_fork_proof`] confirms it independently.
    pub fn check_for_fork(&self, promise: &Promise) -> Option<ForkProof> {
        let record = self.payers.get(promise.payer_pubkey())?;
        let existing = record.retained.get(&promise.seq)?;
        // crate::detect_fork re-checks payer/seq/body, so a duplicate correctly
        // yields None here rather than a bogus "fork".
        crate::verify::detect_fork(existing, promise)
    }

    /// Record a promise this payee has just accepted: advance the payer's chain head
    /// and retain the promise for future fork detection.
    ///
    /// `accepted` is the [`Accepted`] value `verify_promise` returned for this exact
    /// promise; its `new_head` becomes the stored head. Only call this after a
    /// successful verification — recording an unverified promise would corrupt the
    /// head and cause every later promise from that payer to be rejected.
    pub fn record_accepted(&mut self, promise: &Promise, accepted: &Accepted) {
        let payer = *promise.payer_pubkey();
        let retain_limit = self.retain_per_payer;
        let record = self.payers.entry(payer).or_insert_with(|| PayerRecord {
            head: accepted.new_head,
            retained: BTreeMap::new(),
        });
        record.head = accepted.new_head;
        record.retained.insert(promise.seq, promise.clone());

        // Evict the lowest seq while over the cap. BTreeMap keeps keys ordered, so
        // "lowest seq" is the first key — the oldest promise in chain order.
        while record.retained.len() > retain_limit {
            let oldest = match record.retained.keys().next() {
                Some(&k) => k,
                None => break,
            };
            record.retained.remove(&oldest);
        }
    }

    /// Forget a payer entirely (e.g. after settlement, or to reclaim space).
    /// Returns whether anything was removed.
    pub fn forget_payer(&mut self, payer: &PubKeyBytes) -> bool {
        self.payers.remove(payer).is_some()
    }
}
