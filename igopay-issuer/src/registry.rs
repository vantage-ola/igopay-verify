//! Promise registry: dedupe on `(payer_pubkey, seq)` and the fork-proof engine.
//!
//! This closes the one gap a payee cannot close alone (B9). A payee holds only the
//! promises made *to it*, so a payer spending the same `seq` with two different payees
//! is invisible locally. When both payees eventually submit, the registry finds two
//! promises at the same `(payer, seq)` with different signed bodies and emits a
//! [`ForkProof`] — evidence the payer cannot deny, because both promises carry their own
//! hardware signature.
//!
//! ## The registry cannot frame anyone
//!
//! Two properties make this safe to act on:
//!
//! 1. **Nothing is registered unless it verifies.** [`PromiseRegistry::submit`] checks
//!    the issuer signature on the embedded certificate (against *this* issuer's key) and
//!    the payer signature on the promise body, and rejects malleable (high-S) signatures.
//!    A payee cannot poison the registry with a forged promise to get a payer blocked.
//! 2. **A fork proof is re-verifiable by anyone.** The proof the registry emits is the
//!    same artefact `igopay_core::verify_fork_proof` validates, so a payer, another
//!    payee, or an auditor can confirm it independently. The issuer's say-so is not part
//!    of the evidence.
//!
//! ## What it does NOT decide
//!
//! Settlement. An accepted submission means "registered, no fork seen" — never "paid".
//! That distinction lives in [`crate::settlement`] and must survive all the way to the
//! merchant's receipt (`04` use case 1: a receipt says *pending*, never complete).

use igopay_core::crypto::{CryptoError, PubKeyBytes, Verifier};
use igopay_core::{detect_fork, verify_fork_proof, ForkProof, Hash, Promise};
use std::collections::BTreeMap;

/// The outcome of submitting one promise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submission {
    /// First time this issuer has seen this `(payer, seq)`. Now registered.
    Accepted {
        /// Promises this payer has made since the certificate was issued
        /// (`seq - seq_at_issue`) — the same exposure figure the payee priced offline,
        /// now confirmable against the issuer's own record.
        promises_since_issue: u64,
    },
    /// A byte-identical promise is already registered at this `(payer, seq)`.
    /// Resubmission is idempotent — a payee retrying after a failed sync is normal.
    Duplicate,
    /// Same `(payer, seq)`, **different** signed body: the payer double spent. The proof
    /// is returned to the caller and retained, and the payer is added to the block list.
    ///
    /// Boxed because a `ForkProof` carries two whole promises (each with an embedded
    /// certificate) — around 800 bytes — while the common outcomes are 8 bytes or less.
    /// A server returns this value on every submission, and a fork is the rare path, so
    /// the payload does not belong inline.
    Fork(Box<ForkProof>),
}

/// Why a submission was refused. Refusal means nothing was recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitError {
    /// The embedded certificate was not signed by this issuer's key. Either it is
    /// forged, or it belongs to a different issuer.
    BadIssuerSignature,
    /// `sig_payer` did not verify against the certificate's payer key.
    BadPayerSignature,
    /// A signature was well-formed but high-S. Rejected because malleability is a
    /// fork-proof forgery vector (`igopay_core::crypto`).
    MalleableSignature,
    /// A submitted fork proof did not actually prove a fork (same body, different
    /// payers, different seq, or an invalid signature).
    NotAFork,
}

fn map_crypto_err(e: CryptoError, on_fail: SubmitError) -> SubmitError {
    match e {
        CryptoError::HighS => SubmitError::MalleableSignature,
        _ => on_fail,
    }
}

/// The issuer's record of every promise it has been shown, keyed so that a reused `seq`
/// collides.
///
/// Storage here is an in-memory `BTreeMap` because this crate is deliberately
/// persistence-free: a real service swaps in a database behind the same operations. The
/// keying — `(payer_pubkey, seq)` — *is* the design, and it is what a schema must
/// preserve: a unique index on that pair is what makes a double spend a collision
/// instead of two unrelated rows.
#[derive(Debug, Clone)]
pub struct PromiseRegistry {
    issuer_pubkey: PubKeyBytes,
    /// The first promise seen at each `(payer, seq)`. Kept whole, because a fork proof
    /// needs the full signed promise, not a digest.
    seen: BTreeMap<(PubKeyBytes, u64), Promise>,
    /// The first fork proof found per payer. One is enough to block; keeping the first
    /// avoids unbounded growth from a payer who forks repeatedly.
    forks: BTreeMap<PubKeyBytes, ForkProof>,
    /// Blocked payers, mapped to the ordinal at which each was blocked.
    ///
    /// The ordinal is what makes "most recently blocked" answerable, which block-list
    /// publication needs in order to choose which payers go in the exact set rather than
    /// the Bloom filter (B13). Key order alone is public-key order, which is arbitrary.
    blocked: BTreeMap<PubKeyBytes, u64>,
    next_block_ordinal: u64,
}

impl PromiseRegistry {
    /// Create an empty registry for the issuer holding `issuer_pubkey`.
    ///
    /// Every submitted certificate must verify against this key, so a registry only ever
    /// accepts promises descended from its own issuance.
    pub fn new(issuer_pubkey: PubKeyBytes) -> Self {
        PromiseRegistry {
            issuer_pubkey,
            seen: BTreeMap::new(),
            forks: BTreeMap::new(),
            blocked: BTreeMap::new(),
            next_block_ordinal: 0,
        }
    }

    /// Submit one promise, as a payee does when it regains connectivity.
    ///
    /// Signatures are checked first: a promise that does not verify is refused and
    /// nothing is recorded, so the registry cannot be poisoned into blocking an innocent
    /// payer. Then `(payer, seq)` is looked up:
    ///
    /// * unseen → [`Submission::Accepted`];
    /// * seen with the same body digest → [`Submission::Duplicate`] (idempotent);
    /// * seen with a different body digest → [`Submission::Fork`], and the payer is
    ///   blocked.
    ///
    /// A submission from an already-blocked payer is still registered. That is
    /// deliberate: the payee's claim is real and the evidence trail should stay complete;
    /// callers gate on [`is_blocked`](Self::is_blocked) rather than on the registry
    /// silently dropping data.
    pub fn submit<V: Verifier>(
        &mut self,
        promise: &Promise,
        verifier: &V,
    ) -> Result<Submission, SubmitError> {
        let cert = &promise.payer_cert;

        // 1. The certificate must be one WE issued.
        verifier
            .verify_prehash(&self.issuer_pubkey, &cert.body_digest(), &cert.sig_issuer)
            .map_err(|e| map_crypto_err(e, SubmitError::BadIssuerSignature))?;

        // 2. The promise must be signed by the certificate's payer key.
        verifier
            .verify_prehash(
                &cert.payer_pubkey,
                &promise.body_digest(),
                &promise.sig_payer,
            )
            .map_err(|e| map_crypto_err(e, SubmitError::BadPayerSignature))?;

        let payer = *promise.payer_pubkey();
        let key = (payer, promise.seq);

        if let Some(existing) = self.seen.get(&key) {
            // `detect_fork` re-checks payer/seq/body, so a byte-identical resubmission
            // correctly yields None rather than a bogus fork.
            if let Some(proof) = detect_fork(existing, promise) {
                self.block(payer);
                self.forks.entry(payer).or_insert_with(|| proof.clone());
                return Ok(Submission::Fork(Box::new(proof)));
            }
            return Ok(Submission::Duplicate);
        }

        let promises_since_issue = promise.seq.saturating_sub(cert.seq_at_issue);
        self.seen.insert(key, promise.clone());
        Ok(Submission::Accepted {
            promises_since_issue,
        })
    }

    /// Accept a fork proof a payee constructed locally (its `PayeeLedger` caught a
    /// double spend against its own retained promise).
    ///
    /// The proof is **re-verified from scratch** — the issuer never takes a payee's word
    /// for it, because "this payer double spent" is an accusation with consequences.
    /// Returns `true` if this blocked the payer for the first time.
    pub fn submit_fork_proof<V: Verifier>(
        &mut self,
        proof: &ForkProof,
        verifier: &V,
    ) -> Result<bool, SubmitError> {
        if !verify_fork_proof(proof, verifier) {
            return Err(SubmitError::NotAFork);
        }
        // The proof's promises must also descend from a certificate we issued, otherwise
        // it proves a double spend under some other issuer and is not ours to act on.
        for p in [&proof.a, &proof.b] {
            let cert = &p.payer_cert;
            verifier
                .verify_prehash(&self.issuer_pubkey, &cert.body_digest(), &cert.sig_issuer)
                .map_err(|e| map_crypto_err(e, SubmitError::BadIssuerSignature))?;
        }

        let payer = *proof.a.payer_pubkey();
        let newly_blocked = self.block(payer);
        self.forks.entry(payer).or_insert_with(|| proof.clone());
        Ok(newly_blocked)
    }

    /// Record `payer` as blocked, assigning the next block ordinal the first time.
    /// Returns `true` if this was the first block for that payer. Re-blocking keeps the
    /// original ordinal so a payer's position in the recency order never moves.
    fn block(&mut self, payer: PubKeyBytes) -> bool {
        if self.blocked.contains_key(&payer) {
            return false;
        }
        self.blocked.insert(payer, self.next_block_ordinal);
        self.next_block_ordinal += 1;
        true
    }

    /// Is this payer blocked (a fork proof exists for them)?
    pub fn is_blocked(&self, payer: &PubKeyBytes) -> bool {
        self.blocked.contains_key(payer)
    }

    /// Every blocked payer, in stable key order. This is the input to block-list
    /// publication (B13).
    pub fn blocked_payers(&self) -> impl Iterator<Item = &PubKeyBytes> {
        self.blocked.keys()
    }

    /// Blocked payers ordered by when they were blocked, oldest first. Block-list
    /// publication takes the tail of this to fill the exact set (`crate::publish`).
    pub fn blocked_in_block_order(&self) -> Vec<PubKeyBytes> {
        let mut v: Vec<(u64, PubKeyBytes)> = self.blocked.iter().map(|(k, o)| (*o, *k)).collect();
        v.sort_unstable();
        v.into_iter().map(|(_, k)| k).collect()
    }

    /// How many payers are blocked.
    pub fn blocked_count(&self) -> usize {
        self.blocked.len()
    }

    /// The retained fork proof for a payer, if one exists. This is what gets handed to a
    /// payer disputing their block, or to an auditor.
    pub fn fork_proof_for(&self, payer: &PubKeyBytes) -> Option<&ForkProof> {
        self.forks.get(payer)
    }

    /// The registered promise at `(payer, seq)`, if any.
    pub fn promise_at(&self, payer: &PubKeyBytes, seq: u64) -> Option<&Promise> {
        self.seen.get(&(*payer, seq))
    }

    /// The highest `seq` registered for a payer — the issuer's view of how far that
    /// payer's chain has advanced.
    pub fn highest_seq(&self, payer: &PubKeyBytes) -> Option<u64> {
        self.seen
            .range((*payer, 0)..=(*payer, u64::MAX))
            .map(|((_, seq), _)| *seq)
            .next_back()
    }

    /// Total promises registered, across all payers.
    pub fn promise_count(&self) -> usize {
        self.seen.len()
    }

    /// The body digest of every registered promise for a payer, in `seq` order. Useful
    /// for reconciliation against a payee's own record.
    pub fn digests_for_payer(&self, payer: &PubKeyBytes) -> Vec<(u64, Hash)> {
        self.seen
            .range((*payer, 0)..=(*payer, u64::MAX))
            .map(|((_, seq), p)| (*seq, p.body_digest()))
            .collect()
    }
}
