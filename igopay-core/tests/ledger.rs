//! Payee-ledger tests (`src/ledger.rs`).
//!
//! The ledger is what turns stateless verification into a payee that can (a) enforce
//! chain continuity across payments and (b) **produce a fork proof on the spot** when
//! the same payer reuses a `seq` with a different body. These tests drive it through
//! the real `verify_promise` and assert both — plus the bounded-retention behaviour
//! the Android Go memory constraint forces, and the documented limit of what a single
//! payee can detect.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::verify::{verify_promise, VerifyContext, VerifyError};
use igopay_core::{
    verify_fork_proof, BlockList, Certificate, FixedClock, P256Verifier, PayeeLedger, Promise,
    SlotGrant,
};

const NOW: u64 = 1600;

struct Scene {
    issuer: TestSigner,
    payer: TestSigner,
    payee: TestSigner,
    cert: Certificate,
}

fn scene() -> Scene {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let grant = SlotGrant {
        from: 1000,
        to: 1000 + 2880,
        granularity_secs: 60,
    };
    let cert = make_certificate(&issuer, &payer, "adunni", 2, 50_000, grant, 10, 0, 100_000);
    Scene {
        issuer,
        payer,
        payee,
        cert,
    }
}

/// Build a promise from the scene's payer with explicit chain fields.
fn promise_at(s: &Scene, seq: u64, prev_hash: [u8; 32], amount: u64, nonce: &[u8]) -> Promise {
    make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        amount,
        "NGN",
        nonce,
        seq,
        prev_hash,
        1540,
    )
}

/// Verify `promise` using the ledger's stored head for its payer, and record it on
/// success. Mirrors exactly what the app does per payment.
fn verify_and_record(
    s: &Scene,
    ledger: &mut PayeeLedger,
    promise: &Promise,
    nonce: &[u8],
) -> Result<(), VerifyError> {
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let issuer_pk = s.issuer.public_key();
    let payee_pk = s.payee.public_key();
    let ctx = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: nonce,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: ledger.head_for(promise.payer_pubkey()),
    };
    let accepted = verify_promise(promise, &ctx)?;
    ledger.record_accepted(promise, &accepted);
    Ok(())
}

#[test]
fn empty_ledger_has_no_head_and_first_payment_accepts() {
    let s = scene();
    let mut ledger = PayeeLedger::new(8);
    let payer_pk = s.payer.public_key();
    assert!(ledger.head_for(&payer_pk).is_none());
    assert_eq!(ledger.payer_count(), 0);

    let p = promise_at(&s, 11, [0u8; 32], 10_000, b"n1");
    verify_and_record(&s, &mut ledger, &p, b"n1").expect("first payment accepts");

    // The head is now recorded, and matches the promise just accepted.
    let head = ledger.head_for(&payer_pk).expect("head recorded");
    assert_eq!(head.seq, 11);
    assert_eq!(head.body_digest, p.body_digest());
    assert_eq!(ledger.payer_count(), 1);
}

#[test]
fn ledger_head_enforces_chain_continuity_across_payments() {
    // Three linked payments in a row: each one's prev_hash points at the previous
    // body digest, and the ledger supplies the head each time. All must accept.
    let s = scene();
    let mut ledger = PayeeLedger::new(8);

    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");

    let p2 = promise_at(&s, 12, p1.body_digest(), 6_000, b"n2");
    verify_and_record(&s, &mut ledger, &p2, b"n2").expect("p2 links");

    let p3 = promise_at(&s, 13, p2.body_digest(), 7_000, b"n3");
    verify_and_record(&s, &mut ledger, &p3, b"n3").expect("p3 links");

    let head = ledger.head_for(&s.payer.public_key()).unwrap();
    assert_eq!(head.seq, 13);
    assert_eq!(head.body_digest, p3.body_digest());
}

#[test]
fn ledger_head_rejects_broken_link() {
    // A successor whose prev_hash does NOT match the stored head must be rejected —
    // the ledger is what makes this check possible at all.
    let s = scene();
    let mut ledger = PayeeLedger::new(8);

    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");

    // seq 12 but with a garbage prev_hash.
    let bad = promise_at(&s, 12, [0xAAu8; 32], 6_000, b"n2");
    assert!(matches!(
        verify_and_record(&s, &mut ledger, &bad, b"n2"),
        Err(VerifyError::PrevHashMismatch { .. })
    ));
    // The head is unchanged — a rejected promise must not advance state.
    let head = ledger.head_for(&s.payer.public_key()).unwrap();
    assert_eq!(head.seq, 11);
    assert_eq!(head.body_digest, p1.body_digest());
}

#[test]
fn ledger_detects_double_spend_and_produces_a_real_fork_proof() {
    // THE point of retention: the payer reuses seq 11 with a different body. The
    // ledger still holds the original promise, so it can build a fork proof that
    // independently verifies — evidence, not just a rejection.
    let s = scene();
    let mut ledger = PayeeLedger::new(8);

    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");

    // Same payer, same seq, DIFFERENT body (different amount + nonce).
    let p1_fork = promise_at(&s, 11, [0u8; 32], 9_000, b"n2");

    let proof = ledger
        .check_for_fork(&p1_fork)
        .expect("same seq + different body must yield a fork proof");
    assert!(
        verify_fork_proof(&proof, &P256Verifier),
        "the fork proof must independently verify"
    );

    // And verification of the forked promise is rejected on seq grounds too.
    assert!(matches!(
        verify_and_record(&s, &mut ledger, &p1_fork, b"n2"),
        Err(VerifyError::SeqDiscontinuity { .. })
    ));
}

#[test]
fn exact_duplicate_is_not_reported_as_a_fork() {
    // A re-scan of the same QR is a duplicate, not a double spend. It must NOT
    // produce a fork proof (that would be a false accusation).
    let s = scene();
    let mut ledger = PayeeLedger::new(8);
    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");

    // Round-trip through the wire to get an independent but byte-identical copy.
    let same = Promise::from_bytes(&p1.encode()).unwrap();
    assert!(
        ledger.check_for_fork(&same).is_none(),
        "a duplicate must not be reported as a fork"
    );
}

#[test]
fn unknown_payer_and_new_seq_report_no_fork() {
    let s = scene();
    let mut ledger = PayeeLedger::new(8);

    // Nothing recorded yet: no fork possible.
    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    assert!(ledger.check_for_fork(&p1).is_none());

    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");
    // A genuinely new seq is not a fork.
    let p2 = promise_at(&s, 12, p1.body_digest(), 6_000, b"n2");
    assert!(ledger.check_for_fork(&p2).is_none());
}

#[test]
fn retention_is_bounded_and_evicts_the_oldest_seq() {
    // Android Go / ram.low means retention must be capped. With a cap of 2, after
    // three payments only the two most recent seqs are retained, and the evicted one
    // can no longer be used for fork detection — the documented tradeoff.
    let s = scene();
    let mut ledger = PayeeLedger::new(2);

    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");
    let p2 = promise_at(&s, 12, p1.body_digest(), 6_000, b"n2");
    verify_and_record(&s, &mut ledger, &p2, b"n2").expect("p2");
    let p3 = promise_at(&s, 13, p2.body_digest(), 7_000, b"n3");
    verify_and_record(&s, &mut ledger, &p3, b"n3").expect("p3");

    let payer_pk = s.payer.public_key();
    let record = ledger.record_for(&payer_pk).expect("record");
    assert_eq!(record.retained_len(), 2, "retention must respect the cap");
    // seq 11 was evicted (lowest); 12 and 13 remain.
    assert!(
        record.promise_at(11).is_none(),
        "oldest seq must be evicted"
    );
    assert!(record.promise_at(12).is_some());
    assert!(record.promise_at(13).is_some());

    // Consequence, stated honestly: a fork against the EVICTED seq is no longer
    // provable by this payee...
    let fork_of_evicted = promise_at(&s, 11, [0u8; 32], 9_999, b"nX");
    assert!(
        ledger.check_for_fork(&fork_of_evicted).is_none(),
        "evicted evidence cannot produce a proof"
    );
    // ...but a fork against a RETAINED seq still is.
    let fork_of_retained = promise_at(&s, 13, p2.body_digest(), 9_999, b"nY");
    let proof = ledger
        .check_for_fork(&fork_of_retained)
        .expect("retained seq still yields a proof");
    assert!(verify_fork_proof(&proof, &P256Verifier));
}

#[test]
fn retention_cap_of_zero_is_clamped_to_one() {
    // Retaining nothing would silently disable fork detection, so the cap floors at 1.
    let s = scene();
    let mut ledger = PayeeLedger::new(0);
    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");
    let record = ledger.record_for(&s.payer.public_key()).unwrap();
    assert_eq!(record.retained_len(), 1);
    // And that one retained promise is still enough to catch a fork on it.
    let forked = promise_at(&s, 11, [0u8; 32], 9_000, b"n2");
    assert!(ledger.check_for_fork(&forked).is_some());
}

#[test]
fn ledger_tracks_payers_independently() {
    // Two different payers must not interfere: each has its own head, and a seq
    // collision ACROSS payers is not a fork.
    let s = scene();
    let payer2 = TestSigner::from_seed(8);
    let grant = SlotGrant {
        from: 1000,
        to: 1000 + 2880,
        granularity_secs: 60,
    };
    let cert2 = make_certificate(
        &s.issuer, &payer2, "chidi", 2, 50_000, grant, 10, 0, 100_000,
    );

    let mut ledger = PayeeLedger::new(8);

    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("payer1 p1");

    // Payer 2, same seq 11 — a different payer entirely.
    let q1 = make_promise(
        &payer2,
        &cert2,
        s.payee.public_key(),
        5_000,
        "NGN",
        b"n1",
        11,
        [0u8; 32],
        1540,
    );
    // Not a fork: different payer.
    assert!(ledger.check_for_fork(&q1).is_none());

    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let issuer_pk = s.issuer.public_key();
    let payee_pk = s.payee.public_key();
    let ctx = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: b"n1",
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: ledger.head_for(&payer2.public_key()), // None: unseen payer
    };
    let accepted = verify_promise(&q1, &ctx).expect("payer2 first payment accepts");
    ledger.record_accepted(&q1, &accepted);

    assert_eq!(ledger.payer_count(), 2);
    // Heads are independent.
    assert_eq!(ledger.head_for(&s.payer.public_key()).unwrap().seq, 11);
    assert_eq!(ledger.head_for(&payer2.public_key()).unwrap().seq, 11);
    assert_ne!(
        ledger.head_for(&s.payer.public_key()).unwrap().body_digest,
        ledger.head_for(&payer2.public_key()).unwrap().body_digest
    );
}

#[test]
fn forget_payer_clears_state() {
    let s = scene();
    let mut ledger = PayeeLedger::new(8);
    let p1 = promise_at(&s, 11, [0u8; 32], 5_000, b"n1");
    verify_and_record(&s, &mut ledger, &p1, b"n1").expect("p1");
    let payer_pk = s.payer.public_key();

    assert!(ledger.forget_payer(&payer_pk));
    assert!(ledger.head_for(&payer_pk).is_none());
    assert_eq!(ledger.payer_count(), 0);
    // Forgetting again is a no-op.
    assert!(!ledger.forget_payer(&payer_pk));
}
