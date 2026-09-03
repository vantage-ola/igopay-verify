//! The issuer's checkpoint log (B7): its own history, in a form it cannot quietly
//! change.
//!
//! `igopay_core::checkpoint` defines the artefact and every rule a *device* applies to
//! it. This module is the publisher's side: an append-only log that assigns positions,
//! links each entry to the last, and signs. The split is the same one `publish` and
//! `igopay_core::blocklist` already make — one implementation of the wire format and its
//! rules, shared, because a publisher and a phone that disagreed about what a chain link
//! means would be worse than having no chain at all.
//!
//! ## The log is a guard rail before it is evidence
//!
//! It is tempting to read B7 as purely outward-facing: a way for other people to catch a
//! dishonest issuer. But the first thing [`CheckpointLog::append_for_list`] does is refuse
//! to append a list whose epoch does not advance. Before this existed, two racing
//! publisher processes could each ship an epoch-9 block list and nothing anywhere would
//! notice; the two devices that installed them would simply hold different views of who
//! is blocked, forever. Now that is a refused append, at the one place every publication
//! passes through.
//!
//! So the honest framing is: the log makes same-epoch equivocation impossible by
//! accident, and provable when deliberate.
//!
//! ## Storage
//!
//! Entries live in a `Vec` indexed by position, exactly as `registry` keeps every
//! submitted promise in a `BTreeMap`: this crate is deliberately persistence-free, and a
//! real service swaps in a database behind the same operations. What a schema must
//! preserve is the two invariants held here — **one** entry per position, and epochs that
//! strictly increase along it. A unique index on `seq` and a check constraint on `epoch`
//! are the database spelling of this whole module.
//!
//! The log therefore starts at position 0 and stays contiguous. Truncating old history is
//! a service decision, and a service that does it gives up the ability to answer for the
//! part it dropped.

use igopay_core::checkpoint::{
    detect_equivocation, verify_chain_link, verify_checkpoint, Checkpoint, CheckpointError,
    EquivocationProof, GENESIS_PREV,
};
use igopay_core::crypto::{PubKeyBytes, Signer, Verifier};
use igopay_core::{Hash, SignedBlockList};

use crate::publish::{publish_block_list, PublishParams};
use crate::registry::PromiseRegistry;

/// Why an append or a resume was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogError {
    /// The list's epoch is not strictly greater than the head's. This is the guard rail:
    /// an issuer that tries to publish twice at one epoch is stopped here, by its own
    /// code, before any device ever sees two stories.
    EpochNotAdvancing { head: u64, offered: u64 },
    /// The signer offered does not hold the key this log belongs to. Appending with the
    /// wrong key would produce a chain every device rejects — a self-inflicted outage
    /// that would surface hours later on someone's phone, so it is caught here.
    WrongSigner,
    /// Persisted entries did not form a valid chain, so they were not adopted. Carries the
    /// first rule that failed.
    Corrupt(CheckpointError),
    /// Persisted entries did not start at position 0, or skipped a position.
    NotContiguous { expected: u64, got: u64 },
}

impl From<CheckpointError> for LogError {
    fn from(e: CheckpointError) -> Self {
        LogError::Corrupt(e)
    }
}

/// A published block list together with the checkpoint that commits to it. Both are
/// needed on the device: the list to install, the checkpoint to remember what was
/// installed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointedPublication {
    pub list: SignedBlockList,
    pub checkpoint: Checkpoint,
}

/// The issuer's append-only history of what it has published.
#[derive(Debug, Clone)]
pub struct CheckpointLog {
    issuer_pubkey: PubKeyBytes,
    /// Entries indexed by position: `entries[i].seq == i`, always.
    entries: Vec<Checkpoint>,
}

impl CheckpointLog {
    /// An empty log for the issuer holding `issuer_pubkey`.
    pub fn new(issuer_pubkey: PubKeyBytes) -> Self {
        CheckpointLog {
            issuer_pubkey,
            entries: Vec::new(),
        }
    }

    /// Resume from persisted entries, **verifying the whole chain before adopting it**.
    ///
    /// A service restart is the moment a rewrite would be easiest to slip in — the log
    /// comes back from storage nobody re-checked. So resuming re-runs every signature and
    /// every link. It is O(n) elliptic-curve work at startup, which is the right place to
    /// spend it.
    pub fn resume<V: Verifier>(
        issuer_pubkey: PubKeyBytes,
        entries: Vec<Checkpoint>,
        verifier: &V,
    ) -> Result<Self, LogError> {
        for (i, cp) in entries.iter().enumerate() {
            if cp.seq != i as u64 {
                return Err(LogError::NotContiguous {
                    expected: i as u64,
                    got: cp.seq,
                });
            }
        }
        if let Some(first) = entries.first() {
            verify_checkpoint(first, &issuer_pubkey, verifier)?;
        }
        for w in entries.windows(2) {
            verify_chain_link(&w[0], &w[1], &issuer_pubkey, verifier)?;
        }
        Ok(CheckpointLog {
            issuer_pubkey,
            entries,
        })
    }

    /// Append a checkpoint committing to `list`, signed by `signer`.
    ///
    /// The epoch must strictly exceed the head's; the position and the hash link are
    /// assigned here rather than supplied, so a caller cannot create a gap, a duplicate
    /// position, or a broken link even by mistake.
    ///
    /// The list's own signature is not re-checked. It comes from `publish_block_list` with
    /// this same signer — see [`publish_with_checkpoint`], which is the entry point a
    /// service should use precisely so the two artefacts cannot come from different keys.
    pub fn append_for_list<S: Signer>(
        &mut self,
        list: &SignedBlockList,
        issued_at: u64,
        signer: &S,
    ) -> Result<&Checkpoint, LogError> {
        if signer.public_key() != self.issuer_pubkey {
            return Err(LogError::WrongSigner);
        }
        if let Some(head) = self.entries.last() {
            if list.epoch <= head.epoch {
                return Err(LogError::EpochNotAdvancing {
                    head: head.epoch,
                    offered: list.epoch,
                });
            }
        }

        let (seq, prev_hash) = match self.entries.last() {
            None => (0, GENESIS_PREV),
            Some(head) => (head.seq + 1, head.body_digest()),
        };
        let mut cp = Checkpoint {
            seq,
            epoch: list.epoch,
            list_digest: list.body_digest(),
            prev_hash,
            issued_at,
            sig_issuer: [0u8; 64],
        };
        cp.sig_issuer = signer.sign_prehash(&cp.body_digest());
        self.entries.push(cp);
        Ok(self.entries.last().expect("just pushed"))
    }

    /// The most recent entry: what gets anchored, and what a device is told to expect.
    pub fn head(&self) -> Option<&Checkpoint> {
        self.entries.last()
    }

    /// The entry at `seq`.
    pub fn at(&self, seq: u64) -> Option<&Checkpoint> {
        self.entries.get(seq as usize)
    }

    /// Everything after `seq` — what a device holding position `seq` needs in order to
    /// close a gap and verify continuity to the head.
    ///
    /// Small enough to carry: a checkpoint is about 180 bytes, so a device a hundred
    /// publications behind catches up in under 20 KB.
    pub fn since(&self, seq: u64) -> &[Checkpoint] {
        let from = (seq as usize).saturating_add(1).min(self.entries.len());
        &self.entries[from..]
    }

    pub fn entries(&self) -> &[Checkpoint] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The position the next append will take.
    pub fn next_seq(&self) -> u64 {
        self.entries.len() as u64
    }

    /// The issuer this log belongs to.
    pub fn issuer_pubkey(&self) -> &PubKeyBytes {
        &self.issuer_pubkey
    }

    /// Where a checkpoint digest sits in this log, if it is in it at all. This is how an
    /// externally anchored head is matched back to the history
    /// ([`crate::anchor::audit_anchored_head`]).
    pub fn position_of(&self, digest: &Hash) -> Option<u64> {
        self.entries
            .iter()
            .find(|cp| &cp.body_digest() == digest)
            .map(|cp| cp.seq)
    }

    /// Re-verify the entire log: every signature, every link.
    ///
    /// What an auditor runs, and what an issuer should run on itself. An issuer that
    /// cannot produce a log passing this has either lost data or rewritten it, and from
    /// the outside those look identical — which is the point of the exercise.
    pub fn audit<V: Verifier>(&self, verifier: &V) -> Result<(), CheckpointError> {
        if let Some(first) = self.entries.first() {
            verify_checkpoint(first, &self.issuer_pubkey, verifier)?;
        }
        for w in self.entries.windows(2) {
            verify_chain_link(&w[0], &w[1], &self.issuer_pubkey, verifier)?;
        }
        Ok(())
    }

    /// Does a checkpoint somebody was handed contradict this log?
    ///
    /// The dispute-desk operation: a payee turns up saying "this is what I was told", and
    /// this answers whether the log agrees. A returned proof is not the issuer's opinion —
    /// it is two of the issuer's own signatures, checkable by anyone
    /// (`igopay_core::verify_equivocation_proof`).
    ///
    /// Linear here because this crate holds no indexes; a service does the same thing with
    /// a lookup on `seq` and one on `epoch`.
    pub fn conflicting(&self, foreign: &Checkpoint) -> Option<EquivocationProof> {
        self.entries
            .iter()
            .find_map(|mine| detect_equivocation(mine, foreign))
    }
}

/// Publish a block list and checkpoint it in one step.
///
/// This is the entry point a service should call, and the reason it exists is that the two
/// halves must not be separable in practice. A list published without a checkpoint leaves
/// every device that installs it holding no evidence of what it was given, which is the
/// pre-B7 world; and a checkpoint written for a list signed by a different key would
/// produce a commitment no device can satisfy. Doing both here, from one signer, makes
/// both mistakes unavailable.
///
/// The epoch still comes from the caller's persisted counter (`PublishParams`), and the
/// log is what stops a reused one: the append is refused before anything is distributed.
pub fn publish_with_checkpoint<S: Signer>(
    registry: &PromiseRegistry,
    params: &PublishParams,
    signer: &S,
    log: &mut CheckpointLog,
) -> Result<CheckpointedPublication, LogError> {
    // Cheap guards first, so a refused publication costs no filter construction and no
    // signature. Both are re-checked inside `append_for_list`, which stays the single
    // authority on the log's invariants.
    if signer.public_key() != *log.issuer_pubkey() {
        return Err(LogError::WrongSigner);
    }
    if let Some(head) = log.head() {
        if params.epoch <= head.epoch {
            return Err(LogError::EpochNotAdvancing {
                head: head.epoch,
                offered: params.epoch,
            });
        }
    }

    let list = publish_block_list(registry, params, signer);
    let checkpoint = log
        .append_for_list(&list, params.issued_at, signer)?
        .clone();
    Ok(CheckpointedPublication { list, checkpoint })
}
