//! The settlement seam.
//!
//! `08` §6 decision 2: **make the settlement adapter an interface from day one.** The
//! insight behind it (`08` §5) is that the offline *acceptance* layer is the scarce,
//! novel thing, and it is rail-agnostic — whoever ends up moving the money (NIP, a
//! licensed partner, a chain) the promise protocol is identical. One small discipline
//! here keeps the entire rail and jurisdiction question open, and avoids the trap of
//! becoming a regulated money issuer by accident (`08` §5 column C).
//!
//! So only two implementations exist now, and neither moves money:
//!
//! * [`NoOpSettlement`] — records nothing, reports everything as pending forever. The
//!   honest default while the protocol is being proven.
//! * [`ManualSettlement`] — queues promises for a human to settle out of band, which is
//!   how a pilot in one market row would actually work.
//!
//! `NipSettlement` and `SuiSettlement` are later implementations of this same trait.
//!
//! ## Pending is not complete
//!
//! [`SettlementStatus`] has no "accepted" or "confirmed" state that could be mistaken
//! for finality, and `NoOpSettlement` can never return [`SettlementStatus::Settled`].
//! This is load-bearing: `04` use case 1 requires that a merchant's receipt says
//! **pending**, never complete, until the money has actually moved. A settlement
//! adapter that optimistically reported success would reintroduce exactly the
//! false-finality risk the offline design exists to avoid.

use igopay_core::{Hash, Promise};
use std::collections::BTreeMap;

/// Where a promise stands with the settlement rail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementStatus {
    /// Known to the adapter, not yet settled. There is deliberately no distinction
    /// between "queued" and "in flight": to a merchant both mean *not yet paid*.
    Pending,
    /// The money moved. `reference` is the rail's own identifier (a NIP session ID, a
    /// transaction digest) so the claim is auditable outside this system.
    Settled { reference: String },
    /// The rail rejected it. Terminal until someone intervenes.
    Failed { reason: String },
}

impl SettlementStatus {
    /// True only for [`SettlementStatus::Settled`]. Provided so callers express
    /// "is this actually paid?" in one obvious place rather than pattern-matching
    /// loosely and treating `Pending` as success.
    pub fn is_final_success(&self) -> bool {
        matches!(self, SettlementStatus::Settled { .. })
    }
}

/// The rail-independent settlement interface.
///
/// Implementations are free to be entirely inert. The contract is only that `submit`
/// records the promise and returns its current status, and `status` answers for a
/// promise the adapter has seen — never optimistically.
pub trait SettlementAdapter {
    /// A stable identifier for logs and receipts, so a pending promise can always be
    /// traced to the rail that owes it.
    fn name(&self) -> &'static str;

    /// Hand a promise to the rail. Returns its status immediately after submission,
    /// which for every adapter that exists today is [`SettlementStatus::Pending`].
    fn submit(&mut self, promise: &Promise) -> SettlementStatus;

    /// The status of a promise previously submitted, keyed by its body digest (the same
    /// identity the protocol uses for fork detection). `None` if never submitted.
    fn status(&self, promise_digest: &Hash) -> Option<SettlementStatus>;
}

/// Settles nothing, ever. Everything submitted stays [`SettlementStatus::Pending`].
///
/// This is the correct default while the acceptance protocol is being proven: it keeps
/// the seam exercised end to end without any rail, any custody, or any regulatory
/// surface. It records digests so `status` can distinguish "pending" from "never seen",
/// which matters for reconciliation.
#[derive(Debug, Default, Clone)]
pub struct NoOpSettlement {
    seen: BTreeMap<Hash, ()>,
}

impl NoOpSettlement {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many promises have been handed to this adapter.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

impl SettlementAdapter for NoOpSettlement {
    fn name(&self) -> &'static str {
        "noop"
    }

    fn submit(&mut self, promise: &Promise) -> SettlementStatus {
        self.seen.insert(promise.body_digest(), ());
        SettlementStatus::Pending
    }

    fn status(&self, promise_digest: &Hash) -> Option<SettlementStatus> {
        self.seen
            .contains_key(promise_digest)
            .then_some(SettlementStatus::Pending)
    }
}

/// One queued item awaiting human settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualItem {
    pub promise_digest: Hash,
    pub payee_pubkey: igopay_core::PubKeyBytes,
    pub amount: u64,
    pub currency: String,
}

/// Queues promises for a human to settle out of band — a bank transfer, cash, whatever
/// the pilot actually uses. This is the realistic Phase 4 rail for one market row.
///
/// Settlement is recorded by an operator calling [`mark_settled`](Self::mark_settled)
/// with the rail's own reference, so the claim stays auditable outside this system.
#[derive(Debug, Default, Clone)]
pub struct ManualSettlement {
    queue: Vec<ManualItem>,
    status: BTreeMap<Hash, SettlementStatus>,
}

impl ManualSettlement {
    pub fn new() -> Self {
        Self::default()
    }

    /// Everything still awaiting a human, in submission order.
    pub fn pending_queue(&self) -> &[ManualItem] {
        &self.queue
    }

    /// Record that an operator settled a promise on the rail. Removes it from the queue.
    /// Returns false if the digest was never submitted here.
    pub fn mark_settled(&mut self, promise_digest: &Hash, reference: String) -> bool {
        if !self.status.contains_key(promise_digest) {
            return false;
        }
        self.queue.retain(|i| &i.promise_digest != promise_digest);
        self.status
            .insert(*promise_digest, SettlementStatus::Settled { reference });
        true
    }

    /// Record that settlement failed. Also removes it from the queue — a failed item
    /// needs intervention, not a retry loop that hides the problem.
    pub fn mark_failed(&mut self, promise_digest: &Hash, reason: String) -> bool {
        if !self.status.contains_key(promise_digest) {
            return false;
        }
        self.queue.retain(|i| &i.promise_digest != promise_digest);
        self.status
            .insert(*promise_digest, SettlementStatus::Failed { reason });
        true
    }
}

impl SettlementAdapter for ManualSettlement {
    fn name(&self) -> &'static str {
        "manual"
    }

    fn submit(&mut self, promise: &Promise) -> SettlementStatus {
        let digest = promise.body_digest();
        // Idempotent: resubmitting an already-known promise must not double-queue it.
        if let Some(existing) = self.status.get(&digest) {
            return existing.clone();
        }
        self.queue.push(ManualItem {
            promise_digest: digest,
            payee_pubkey: promise.payee_pubkey,
            amount: promise.amount,
            currency: promise.currency.clone(),
        });
        self.status.insert(digest, SettlementStatus::Pending);
        SettlementStatus::Pending
    }

    fn status(&self, promise_digest: &Hash) -> Option<SettlementStatus> {
        self.status.get(promise_digest).cloned()
    }
}
