//! Settlement-seam tests.
//!
//! The property that actually matters here is a *negative* one: no adapter may ever
//! report a promise as settled unless it genuinely was. `04` use case 1 requires a
//! merchant's receipt to say **pending**, never complete, until money has moved — so a
//! `NoOpSettlement` that optimistically returned success would reintroduce exactly the
//! false-finality risk the offline design exists to avoid.

mod common;

use common::{issue_cert, promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_issuer::{ManualSettlement, NoOpSettlement, SettlementAdapter, SettlementStatus};

const SLOT: u64 = 1540;

fn a_promise(amount: u64, nonce: &[u8], seq: u64) -> igopay_core::Promise {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let cert = issue_cert(&issuer, &payer, 10);
    promise(
        &payer,
        &cert,
        payee.public_key(),
        amount,
        nonce,
        seq,
        [0u8; 32],
        SLOT,
    )
}

#[test]
fn noop_never_reports_settled() {
    let mut a = NoOpSettlement::new();
    let p = a_promise(10_000, b"n1", 11);
    assert_eq!(a.name(), "noop");

    let status = a.submit(&p);
    assert_eq!(status, SettlementStatus::Pending);
    assert!(!status.is_final_success(), "pending is not success");

    // Still pending on every later query — there is no path to Settled at all.
    assert_eq!(a.status(&p.body_digest()), Some(SettlementStatus::Pending));
    assert_eq!(a.len(), 1);
}

#[test]
fn noop_distinguishes_pending_from_never_seen() {
    // Reconciliation needs this: "we hold this promise, unsettled" is a different fact
    // from "we have never heard of it".
    let mut a = NoOpSettlement::new();
    let seen = a_promise(10_000, b"n1", 11);
    let unseen = a_promise(20_000, b"n2", 12);
    a.submit(&seen);

    assert_eq!(
        a.status(&seen.body_digest()),
        Some(SettlementStatus::Pending)
    );
    assert_eq!(a.status(&unseen.body_digest()), None);
}

#[test]
fn manual_queues_and_is_idempotent() {
    let mut a = ManualSettlement::new();
    let p = a_promise(10_000, b"n1", 11);
    assert_eq!(a.name(), "manual");

    assert_eq!(a.submit(&p), SettlementStatus::Pending);
    assert_eq!(a.pending_queue().len(), 1);
    let item = &a.pending_queue()[0];
    assert_eq!(item.promise_digest, p.body_digest());
    assert_eq!(item.amount, 10_000);
    assert_eq!(item.currency, "NGN");

    // Resubmitting the same promise must not double-queue it — a payee retrying a sync
    // would otherwise create duplicate payouts.
    assert_eq!(a.submit(&p), SettlementStatus::Pending);
    assert_eq!(a.pending_queue().len(), 1);
}

#[test]
fn manual_settlement_requires_an_operator_and_a_reference() {
    let mut a = ManualSettlement::new();
    let p = a_promise(10_000, b"n1", 11);
    a.submit(&p);
    let digest = p.body_digest();

    // Nothing is settled until an operator says so.
    assert_eq!(a.status(&digest), Some(SettlementStatus::Pending));

    assert!(a.mark_settled(&digest, "NIP-REF-12345".into()));
    assert_eq!(
        a.status(&digest),
        Some(SettlementStatus::Settled {
            reference: "NIP-REF-12345".into()
        })
    );
    assert!(a.status(&digest).unwrap().is_final_success());
    // Settled items leave the queue.
    assert!(a.pending_queue().is_empty());
}

#[test]
fn manual_failure_is_terminal_and_leaves_the_queue() {
    let mut a = ManualSettlement::new();
    let p = a_promise(10_000, b"n1", 11);
    a.submit(&p);
    let digest = p.body_digest();

    assert!(a.mark_failed(&digest, "account closed".into()));
    assert_eq!(
        a.status(&digest),
        Some(SettlementStatus::Failed {
            reason: "account closed".into()
        })
    );
    assert!(!a.status(&digest).unwrap().is_final_success());
    assert!(
        a.pending_queue().is_empty(),
        "a failed item needs intervention, not a silent retry loop"
    );
}

#[test]
fn marking_an_unknown_promise_is_refused() {
    // An operator cannot mark something settled that was never submitted — that would be
    // a payout with no claim behind it.
    let mut a = ManualSettlement::new();
    let unknown = a_promise(10_000, b"n1", 11).body_digest();
    assert!(!a.mark_settled(&unknown, "ref".into()));
    assert!(!a.mark_failed(&unknown, "reason".into()));
    assert_eq!(a.status(&unknown), None);
}

#[test]
fn adapters_are_interchangeable_through_the_trait() {
    // The whole point of the seam (`08` §6): callers depend on the trait, so swapping in
    // NipSettlement or SuiSettlement later is a substitution, not a rewrite.
    fn submit_all(adapter: &mut dyn SettlementAdapter, ps: &[igopay_core::Promise]) -> usize {
        ps.iter()
            .filter(|p| adapter.submit(p) == SettlementStatus::Pending)
            .count()
    }
    let promises = vec![a_promise(1_000, b"n1", 11), a_promise(2_000, b"n2", 12)];

    let mut noop = NoOpSettlement::new();
    let mut manual = ManualSettlement::new();
    assert_eq!(submit_all(&mut noop, &promises), 2);
    assert_eq!(submit_all(&mut manual, &promises), 2);
    assert_eq!(manual.pending_queue().len(), 2);
}
