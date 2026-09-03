//! The external anchor seam (B7's other half).
//!
//! A checkpoint chain makes the issuer's history *self-consistent or provably not*. It
//! does not make anyone look. Two devices that never meet can be told two different
//! histories indefinitely, and each will verify happily, because everything it holds
//! agrees with everything else it holds.
//!
//! An anchor is the fix, and it is deliberately unglamorous: put the head of the log
//! somewhere a stranger can read it, so that "which history is the real one" has a public
//! answer. This is the Certificate Transparency division of labour — the log makes
//! misbehaviour undeniable, witnesses and gossip make it visible — and the anchor is our
//! witness slot.
//!
//! ## Why this is an interface with almost nothing behind it
//!
//! The same reason [`crate::settlement`] is (`08` §6 decision 2): the choice of *where* to
//! anchor is unsettled, and picking one now would be picking a jurisdiction, a cost model
//! and an operational dependency at the same time. Candidates, all of which are later
//! implementations of this one trait:
//!
//! * **OpenTimestamps** — a Bitcoin-anchored timestamp on the head digest. Free, no
//!   account, no token, but confirmation is slow (`idea/tap-toy-protocol.md` §10).
//! * **A Certificate Transparency-style witness** — another party co-signs the head. Fast
//!   and cheap; needs someone willing to be that party.
//! * **A chain object** — `08` §4.2 goes further and proposes replacing the issuer's log
//!   with on-chain per-payer version conflicts, which would remove the issuer as a trusted
//!   party rather than merely watching it. That substitution is the reason this is a seam
//!   and not a hard-coded HTTP call.
//! * **Something embarrassingly simple** — the head digest posted to a public channel, or
//!   committed to a public git repository. Weak on availability guarantees, strong on
//!   "anyone can check", and enough to make a split view risky for the issuer. Not to be
//!   dismissed for a pilot in one market row.
//!
//! ## Unanchored is the honest default, and it says so
//!
//! [`NoOpAnchor`] accepts submissions and reports [`AnchorStatus::Unanchored`] forever. It
//! **cannot** return [`AnchorStatus::Anchored`], exactly as `NoOpSettlement` cannot return
//! `Settled`. The failure mode being designed out is the same one: a component that
//! optimistically claims success teaches everything above it to trust something that never
//! happened. An operations dashboard reading "anchored" while nothing was ever published
//! would be worse than no anchor at all, because the point of the mechanism is to make
//! quiet divergence loud.
//!
//! For the same reason [`AnchorStatus::Pending`] is not a success state. An OpenTimestamps
//! attestation that has not been confirmed, or an unconfirmed transaction, is not yet
//! something a third party can read.

use igopay_core::checkpoint::Checkpoint;
use igopay_core::crypto::{PubKeyBytes, Verifier};
use igopay_core::witness::{Cosignature, WitnessedCheckpoint};
use igopay_core::Hash;
use std::collections::BTreeMap;

use crate::checkpoint::CheckpointLog;

/// Where a checkpoint stands with the outside world.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorStatus {
    /// Not published anywhere a stranger can read. Carries no evidential weight and is
    /// never dressed up as though it does.
    Unanchored,
    /// Handed to an anchor, not yet externally readable — a pending timestamp
    /// attestation, an unconfirmed transaction. Still not evidence.
    Pending { submitted_at: u64 },
    /// Externally visible. `reference` is the outside world's own identifier for it (an
    /// OpenTimestamps proof file, a log index, a transaction digest), so the claim can be
    /// checked without asking us anything.
    Anchored {
        reference: String,
        confirmed_at: u64,
    },
}

impl AnchorStatus {
    /// True only for [`AnchorStatus::Anchored`]. Provided so callers ask "can an outsider
    /// actually see this?" in one obvious place, instead of pattern-matching loosely and
    /// letting `Pending` drift into meaning success.
    pub fn is_publicly_visible(&self) -> bool {
        matches!(self, AnchorStatus::Anchored { .. })
    }
}

/// The anchor-independent interface.
///
/// Implementations may be entirely inert. The contract is only that `submit` records the
/// checkpoint and returns its status honestly, and that `status` answers for a checkpoint
/// the sink has seen — never optimistically.
pub trait AnchorSink {
    /// A stable identifier for logs and operator dashboards, so an unanchored head can
    /// always be traced to the sink that was supposed to publish it.
    fn name(&self) -> &'static str;

    /// Hand a checkpoint to the anchor. Returns its status immediately after submission.
    fn submit(&mut self, checkpoint: &Checkpoint) -> AnchorStatus;

    /// The status of a checkpoint previously submitted, keyed by
    /// [`Checkpoint::body_digest`] — the same identity the chain links on. `None` if it was
    /// never submitted here.
    fn status(&self, checkpoint_digest: &Hash) -> Option<AnchorStatus>;
}

/// Anchors nothing, anywhere. Everything submitted stays [`AnchorStatus::Unanchored`].
///
/// The correct default while there is no chosen anchor: it keeps the seam exercised end to
/// end, and it tells the truth about the resulting guarantee — equivocation is provable
/// once two views meet, and nothing is watching for that yet. Digests are recorded so
/// `status` can distinguish "unanchored" from "never submitted", which is the difference
/// between a sink that is inert and a publication path that silently skipped it.
#[derive(Debug, Default, Clone)]
pub struct NoOpAnchor {
    seen: BTreeMap<Hash, ()>,
}

impl NoOpAnchor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl AnchorSink for NoOpAnchor {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn submit(&mut self, checkpoint: &Checkpoint) -> AnchorStatus {
        self.seen.insert(checkpoint.body_digest(), ());
        AnchorStatus::Unanchored
    }

    fn status(&self, checkpoint_digest: &Hash) -> Option<AnchorStatus> {
        self.seen
            .contains_key(checkpoint_digest)
            .then_some(AnchorStatus::Unanchored)
    }
}

/// One head waiting for a human to publish it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAnchor {
    pub checkpoint_digest: Hash,
    pub seq: u64,
    pub epoch: u64,
    pub submitted_at: u64,
}

/// Queues heads for a human to publish out of band, and records the external reference
/// they come back with.
///
/// This is the realistic first anchor: an operator posts the head digest somewhere public
/// and pastes back the link. Unglamorous, and it already changes the game — an issuer that
/// has published epoch 9's digest publicly cannot hand anyone a different epoch 9 without
/// the two being comparable by a stranger.
///
/// [`confirm`](Self::confirm) requires a non-empty reference, mirroring
/// `ManualSettlement::mark_settled`: a claim of external visibility with nothing to point
/// at is exactly the false assurance this whole module is built to refuse.
#[derive(Debug, Default, Clone)]
pub struct ManualAnchor {
    queue: Vec<PendingAnchor>,
    status: BTreeMap<Hash, AnchorStatus>,
}

impl ManualAnchor {
    pub fn new() -> Self {
        Self::default()
    }

    /// Heads still awaiting a human, in submission order.
    pub fn pending_queue(&self) -> &[PendingAnchor] {
        &self.queue
    }

    /// Record that an operator published this head, with the external reference proving
    /// it. Removes it from the queue.
    ///
    /// Returns false if the digest was never submitted here, or if `reference` is empty.
    pub fn confirm(&mut self, checkpoint_digest: &Hash, reference: String, at: u64) -> bool {
        if reference.trim().is_empty() || !self.status.contains_key(checkpoint_digest) {
            return false;
        }
        self.queue
            .retain(|p| &p.checkpoint_digest != checkpoint_digest);
        self.status.insert(
            *checkpoint_digest,
            AnchorStatus::Anchored {
                reference,
                confirmed_at: at,
            },
        );
        true
    }

    /// The most recently confirmed head, if any: what an operator quotes when asked
    /// "where can I check you?".
    pub fn latest_anchored(&self) -> Option<(&Hash, &AnchorStatus)> {
        self.status
            .iter()
            .filter(|(_, s)| s.is_publicly_visible())
            .max_by_key(|(_, s)| match s {
                AnchorStatus::Anchored { confirmed_at, .. } => *confirmed_at,
                _ => 0,
            })
    }
}

impl AnchorSink for ManualAnchor {
    fn name(&self) -> &'static str {
        "manual"
    }

    fn submit(&mut self, checkpoint: &Checkpoint) -> AnchorStatus {
        let digest = checkpoint.body_digest();
        // Idempotent: resubmitting a head must not double-queue it, and must never undo a
        // confirmation.
        if let Some(existing) = self.status.get(&digest) {
            return existing.clone();
        }
        self.queue.push(PendingAnchor {
            checkpoint_digest: digest,
            seq: checkpoint.seq,
            epoch: checkpoint.epoch,
            submitted_at: checkpoint.issued_at,
        });
        let status = AnchorStatus::Pending {
            submitted_at: checkpoint.issued_at,
        };
        self.status.insert(digest, status.clone());
        status
    }

    fn status(&self, checkpoint_digest: &Hash) -> Option<AnchorStatus> {
        self.status.get(checkpoint_digest).cloned()
    }
}

/// Collects witness cosignatures on published heads (`igopay_core::witness`).
///
/// The other two sinks make a head *readable* by someone who is online. This one makes it
/// **checkable by a payee who is not**: the cosignatures it collects are attached to the
/// checkpoint and travel with the block list, so a trader verifies a second signature at the
/// counter instead of trusting that an auditor will look later. That is why this, not the
/// public mirror, is the anchor that changes what a merchant can rely on.
///
/// The service loop it belongs in:
///
/// 1. `publish_with_checkpoint` → a list and a checkpoint;
/// 2. `submit` the checkpoint here → [`AnchorStatus::Pending`];
/// 3. send the checkpoint to each witness and collect what comes back;
/// 4. [`record_cosignature`](Self::record_cosignature) each one — at the threshold the
///    status becomes [`AnchorStatus::Anchored`];
/// 5. [`witnessed`](Self::witnessed) to build the artefact that ships with the list.
///
/// A witness that **refuses** returns an equivocation proof instead of a signature
/// (`igopay_core::witness::WitnessRefusal`). That is not an error condition to retry around:
/// it means the issuer just asked to have two heads attested at one position, and the honest
/// response is to stop publishing and work out which process produced the second one.
#[derive(Debug, Clone)]
pub struct WitnessAnchor {
    issuer_pubkey: PubKeyBytes,
    witnesses: Vec<PubKeyBytes>,
    min_witnesses: usize,
    /// Submitted heads, by checkpoint digest, with whatever has been collected for each.
    collected: BTreeMap<Hash, WitnessedCheckpoint>,
}

impl WitnessAnchor {
    /// Collect for the issuer holding `issuer_pubkey`, trusting `witnesses`, and treat a head
    /// as anchored once `min_witnesses` distinct ones have cosigned (clamped to at least 1 —
    /// a threshold of zero would mean "anchored with no attestation", which is the lie this
    /// whole module refuses).
    ///
    /// With an empty witness set nothing can ever reach `Anchored`. That is the honest
    /// outcome, not a bug: no witnesses means no attestation.
    pub fn new(
        issuer_pubkey: PubKeyBytes,
        witnesses: Vec<PubKeyBytes>,
        min_witnesses: usize,
    ) -> Self {
        WitnessAnchor {
            issuer_pubkey,
            witnesses,
            min_witnesses: min_witnesses.max(1),
            collected: BTreeMap::new(),
        }
    }

    /// Record a cosignature a witness returned.
    ///
    /// Verified before it is kept, and refused unless it comes from a trusted witness, names
    /// *this* issuer, and names a head this sink actually submitted. Returns whether it was
    /// recorded.
    ///
    /// An issuer that accepted unverified cosignatures would ship artefacts every device
    /// rejects — the same class of self-inflicted outage `CheckpointLog::append_for_list`
    /// guards against by checking the signing key.
    pub fn record_cosignature<V: Verifier>(&mut self, cosig: Cosignature, verifier: &V) -> bool {
        if !self.witnesses.contains(&cosig.witness_pubkey)
            || cosig.issuer_pubkey != self.issuer_pubkey
        {
            return false;
        }
        if cosig.verify(verifier).is_err() {
            return false;
        }
        match self.collected.get_mut(&cosig.checkpoint_digest) {
            Some(entry) => entry.attach(cosig),
            None => false,
        }
    }

    /// The artefact to distribute alongside the block list: the checkpoint plus every
    /// cosignature collected for it so far.
    pub fn witnessed(&self, checkpoint_digest: &Hash) -> Option<&WitnessedCheckpoint> {
        self.collected.get(checkpoint_digest)
    }

    /// How many trusted witnesses have cosigned this head.
    pub fn coverage(&self, checkpoint_digest: &Hash) -> usize {
        self.collected
            .get(checkpoint_digest)
            .map(|wc| wc.cosignatures.len())
            .unwrap_or(0)
    }

    /// The threshold at which a head is treated as anchored.
    pub fn min_witnesses(&self) -> usize {
        self.min_witnesses
    }

    fn status_for(&self, wc: &WitnessedCheckpoint) -> AnchorStatus {
        if wc.cosignatures.len() < self.min_witnesses {
            return AnchorStatus::Pending {
                submitted_at: wc.checkpoint.issued_at,
            };
        }
        // The reference identifies who attested, so an auditor knows whose signature to ask
        // for. The signatures themselves live in the artefact, not in this string.
        let mut reference = String::from("witness:");
        for (i, c) in wc.cosignatures.iter().enumerate() {
            if i > 0 {
                reference.push('+');
            }
            for b in &c.witness_pubkey[..4] {
                reference.push_str(&format!("{b:02x}"));
            }
        }
        let confirmed_at = wc
            .cosignatures
            .iter()
            .map(|c| c.signed_at)
            .max()
            .unwrap_or(wc.checkpoint.issued_at);
        AnchorStatus::Anchored {
            reference,
            confirmed_at,
        }
    }
}

impl AnchorSink for WitnessAnchor {
    fn name(&self) -> &'static str {
        "witness"
    }

    fn submit(&mut self, checkpoint: &Checkpoint) -> AnchorStatus {
        let digest = checkpoint.body_digest();
        // Idempotent, and never destructive: resubmitting a head must not discard
        // cosignatures already collected for it.
        let entry = self
            .collected
            .entry(digest)
            .or_insert_with(|| WitnessedCheckpoint::new(checkpoint.clone()));
        let snapshot = entry.clone();
        self.status_for(&snapshot)
    }

    fn status(&self, checkpoint_digest: &Hash) -> Option<AnchorStatus> {
        self.collected
            .get(checkpoint_digest)
            .map(|wc| self.status_for(wc))
    }
}

/// What an externally-read head digest says about a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorAudit {
    /// The anchored digest is this log's current head. Fully reconciled.
    HeadMatches { seq: u64 },
    /// The anchored digest is an earlier entry in this log. Normal: anchoring lags
    /// publication, so the log has simply moved on. Everything up to `seq` is publicly
    /// pinned; everything after it rests on the issuer's word until the next anchor.
    Behind { seq: u64, head: u64 },
    /// The anchored digest is not in this log at all.
    ///
    /// The alarm. Either this is not the log that was anchored, or the log has been
    /// rewritten since. Note what it is not: a proof. To *prove* the rewrite somebody must
    /// still hold the signed checkpoint that was anchored — the digest alone shows a
    /// mismatch, not who signed what. Anchoring the digest and keeping the checkpoint it
    /// came from are therefore both necessary.
    NotInLog,
    /// Nothing has been anchored, or the log is empty. No claim either way.
    Nothing,
}

/// Reconcile a head digest read from the public anchor against a local log.
///
/// The whole audit, in one function, and deliberately callable by anyone: read the digest
/// from wherever it was posted, ask the issuer for its log, and compare. An auditor needs
/// no credentials and no cooperation beyond a copy of the log — which is the property that
/// makes this worth building at all.
pub fn audit_anchored_head(log: &CheckpointLog, anchored_digest: Option<&Hash>) -> AnchorAudit {
    let (Some(digest), Some(head)) = (anchored_digest, log.head()) else {
        return AnchorAudit::Nothing;
    };
    match log.position_of(digest) {
        None => AnchorAudit::NotInLog,
        Some(seq) if seq == head.seq => AnchorAudit::HeadMatches { seq },
        Some(seq) => AnchorAudit::Behind {
            seq,
            head: head.seq,
        },
    }
}
