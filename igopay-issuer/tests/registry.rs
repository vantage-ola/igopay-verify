//! Registry tests — the cross-payee fork detection that closes the B9 gap.
//!
//! The headline case is `cross_payee_double_spend_is_caught_by_the_issuer`: two payees
//! that each accepted a promise at the same `seq` cannot detect the fork locally
//! (`igopay_core::PayeeLedger` documents exactly that limit), but the issuer sees both
//! submissions and produces a proof that verifies independently.
//!
//! The rest guard the properties that make the registry safe to act on: it refuses
//! anything that does not verify, it never reports a duplicate as a fork, and it will not
//! take a payee's word for an accusation.

mod common;

use common::{issue_cert, promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::{build_certificate, verify_fork_proof, P256Verifier, SlotGrant};
use igopay_issuer::{PromiseRegistry, Submission, SubmitError};

const SLOT: u64 = 1540;

struct Scene {
    issuer: TestSigner,
    payer: TestSigner,
    payee_a: TestSigner,
    payee_b: TestSigner,
    cert: igopay_core::Certificate,
}

fn scene() -> Scene {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee_a = TestSigner::from_seed(3);
    let payee_b = TestSigner::from_seed(4);
    let cert = issue_cert(&issuer, &payer, 10);
    Scene {
        issuer,
        payer,
        payee_a,
        payee_b,
        cert,
    }
}

fn registry(s: &Scene) -> PromiseRegistry {
    PromiseRegistry::new(s.issuer.public_key())
}

#[test]
fn first_submission_is_accepted_with_exposure() {
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let p = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    // seq 11, seq_at_issue 10 -> one promise since issue, matching what the payee priced.
    assert_eq!(
        reg.submit(&p, &v),
        Ok(Submission::Accepted {
            promises_since_issue: 1
        })
    );
    assert_eq!(reg.promise_count(), 1);
    assert!(!reg.is_blocked(&s.payer.public_key()));
    assert_eq!(reg.highest_seq(&s.payer.public_key()), Some(11));
}

#[test]
fn identical_resubmission_is_idempotent() {
    // A payee retrying after a failed sync must not look like a double spend.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let p = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    reg.submit(&p, &v).unwrap();
    assert_eq!(reg.submit(&p, &v), Ok(Submission::Duplicate));
    // Round-tripping through the wire must also be recognised as the same promise.
    let wire_copy = igopay_core::Promise::from_bytes(&p.encode()).unwrap();
    assert_eq!(reg.submit(&wire_copy, &v), Ok(Submission::Duplicate));

    assert_eq!(reg.promise_count(), 1);
    assert!(!reg.is_blocked(&s.payer.public_key()));
}

#[test]
fn cross_payee_double_spend_is_caught_by_the_issuer() {
    // THE case the issuer exists for (B9). Payee A and payee B each accepted a promise at
    // seq 11. Neither can see the other's promise, so neither can prove a fork. The
    // issuer sees both.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let to_a = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"nonce-a",
        11,
        [0u8; 32],
        SLOT,
    );
    let to_b = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        25_000,
        b"nonce-b",
        11, // SAME seq, different body
        [0u8; 32],
        SLOT,
    );

    // Payee A syncs first: nothing suspicious yet.
    assert_eq!(
        reg.submit(&to_a, &v),
        Ok(Submission::Accepted {
            promises_since_issue: 1
        })
    );
    assert!(!reg.is_blocked(&s.payer.public_key()));

    // Payee B syncs: the collision surfaces.
    let outcome = reg.submit(&to_b, &v).expect("submission verifies");
    let proof = match outcome {
        Submission::Fork(p) => *p,
        other => panic!("expected a fork, got {:?}", other),
    };

    // The proof must stand on its own — anyone can confirm it without trusting the issuer.
    assert!(
        verify_fork_proof(&proof, &v),
        "issuer-derived fork proof must independently verify"
    );
    // The payer is blocked, and the proof is retained for a dispute or an audit.
    assert!(reg.is_blocked(&s.payer.public_key()));
    assert_eq!(reg.fork_proof_for(&s.payer.public_key()), Some(&proof));
    assert_eq!(
        reg.blocked_payers().collect::<Vec<_>>(),
        vec![&s.payer.public_key()]
    );
}

#[test]
fn fork_proof_survives_serialization_from_the_registry() {
    // The proof is portable evidence (B8): the issuer must be able to hand it over the
    // wire and have it verify on the other side.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let a = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"na",
        11,
        [0u8; 32],
        SLOT,
    );
    let b = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        25_000,
        b"nb",
        11,
        [0u8; 32],
        SLOT,
    );
    reg.submit(&a, &v).unwrap();
    let proof = match reg.submit(&b, &v).unwrap() {
        Submission::Fork(p) => *p,
        other => panic!("expected fork, got {:?}", other),
    };

    let bytes = proof.encode();
    let decoded = igopay_core::ForkProof::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, proof);
    assert_eq!(decoded.encode(), bytes, "encoding must be canonical");
    assert!(verify_fork_proof(&decoded, &v));
}

#[test]
fn different_seq_from_same_payer_is_not_a_fork() {
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let p1 = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        5_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    let p2 = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        6_000,
        b"n2",
        12, // advancing normally
        p1.body_digest(),
        1600,
    );
    reg.submit(&p1, &v).unwrap();
    assert_eq!(
        reg.submit(&p2, &v),
        Ok(Submission::Accepted {
            promises_since_issue: 2
        })
    );
    assert!(!reg.is_blocked(&s.payer.public_key()));
    assert_eq!(reg.highest_seq(&s.payer.public_key()), Some(12));
}

#[test]
fn same_seq_from_different_payers_is_not_a_fork() {
    // Two payers legitimately both have a seq 11. Keying on (payer, seq) must keep them
    // apart — a shared seq counter would produce false accusations constantly.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let payer2 = TestSigner::from_seed(8);
    let cert2 = issue_cert(&s.issuer, &payer2, 10);

    let p1 = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        5_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    let q1 = promise(
        &payer2,
        &cert2,
        s.payee_a.public_key(),
        7_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    reg.submit(&p1, &v).unwrap();
    assert!(matches!(
        reg.submit(&q1, &v),
        Ok(Submission::Accepted { .. })
    ));
    assert!(!reg.is_blocked(&s.payer.public_key()));
    assert!(!reg.is_blocked(&payer2.public_key()));
    assert_eq!(reg.promise_count(), 2);
}

#[test]
fn promise_with_a_forged_payer_signature_is_refused_and_records_nothing() {
    // The registry must not be poisonable. A payee that fabricates a promise cannot get
    // a payer blocked, and cannot even get it stored.
    //
    // The forgery is a *valid, low-S* signature over a DIFFERENT promise body, lifted
    // onto this one. That is the realistic attack shape and it isolates the
    // wrong-message rejection path from the malleability one below.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let other = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        99_000,
        b"other",
        77,
        [0u8; 32],
        SLOT,
    );
    let mut forged = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    forged.sig_payer = other.sig_payer; // valid signature, wrong message

    assert_eq!(reg.submit(&forged, &v), Err(SubmitError::BadPayerSignature));
    assert_eq!(reg.promise_count(), 0, "nothing may be recorded");
    assert!(!reg.is_blocked(&s.payer.public_key()));
}

#[test]
fn malleated_high_s_promise_is_refused_at_the_issuer() {
    // A high-S copy of an honest promise verifies fine as raw ECDSA but has different
    // bytes, so accepting it would let an attacker manufacture a "second promise at the
    // same seq" and frame the payer. The core rejects high-S and the issuer must inherit
    // that, with the reason preserved so it is diagnosable.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let honest = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    let mut malleated = honest.clone();
    malleated.sig_payer = TestSigner::malleate(&honest.sig_payer);
    assert_ne!(malleated.sig_payer, honest.sig_payer);

    assert_eq!(
        reg.submit(&malleated, &v),
        Err(SubmitError::MalleableSignature)
    );
    assert_eq!(reg.promise_count(), 0);
    assert!(!reg.is_blocked(&s.payer.public_key()));

    // And the honest original still registers cleanly afterwards.
    assert!(matches!(
        reg.submit(&honest, &v),
        Ok(Submission::Accepted { .. })
    ));
}

#[test]
fn certificate_from_another_issuer_is_refused() {
    // A promise descended from someone else's certificate is not ours to register or act
    // on, even though it is internally valid.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let other_issuer = TestSigner::from_seed(9);
    let foreign_cert = build_certificate(
        &other_issuer,
        s.payer.public_key(),
        "adunni".into(),
        2,
        50_000,
        SlotGrant {
            from: 1000,
            to: 3880,
            granularity_secs: 60,
        },
        10,
        0,
        100_000,
    );
    let p = promise(
        &s.payer,
        &foreign_cert,
        s.payee_a.public_key(),
        10_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    assert_eq!(reg.submit(&p, &v), Err(SubmitError::BadIssuerSignature));
    assert_eq!(reg.promise_count(), 0);
}

#[test]
fn payee_submitted_fork_proof_is_reverified_then_accepted() {
    // A payee's own PayeeLedger caught a double spend against its retained promise. The
    // issuer must re-verify from scratch rather than trust the accusation.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let a = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"na",
        11,
        [0u8; 32],
        SLOT,
    );
    let b = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        20_000,
        b"nb",
        11,
        [0u8; 32],
        SLOT,
    );
    let proof = igopay_core::detect_fork(&a, &b).expect("genuine fork");

    assert_eq!(reg.submit_fork_proof(&proof, &v), Ok(true), "newly blocked");
    assert!(reg.is_blocked(&s.payer.public_key()));
    // Submitting it again is idempotent and reports "not newly blocked".
    assert_eq!(reg.submit_fork_proof(&proof, &v), Ok(false));
}

#[test]
fn fabricated_fork_proof_is_rejected_and_blocks_nobody() {
    // Structurally a fork, but one signature is garbage. The issuer must refuse it —
    // otherwise a payee could block any payer by inventing a second promise.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let a = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"na",
        11,
        [0u8; 32],
        SLOT,
    );
    let mut b = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        20_000,
        b"nb",
        11,
        [0u8; 32],
        SLOT,
    );
    b.sig_payer = [0xCDu8; 64];
    let bogus = igopay_core::detect_fork(&a, &b).expect("structurally a fork");

    assert_eq!(
        reg.submit_fork_proof(&bogus, &v),
        Err(SubmitError::NotAFork)
    );
    assert!(
        !reg.is_blocked(&s.payer.public_key()),
        "a fabricated proof must never block a payer"
    );
    assert!(reg.fork_proof_for(&s.payer.public_key()).is_none());
}

#[test]
fn duplicate_promise_pair_is_not_accepted_as_a_fork_proof() {
    // Two byte-identical promises are a duplicate, not evidence. detect_fork already
    // refuses to build a proof, so construct one by hand to prove the registry's own
    // check is what rejects it.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let p = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"na",
        11,
        [0u8; 32],
        SLOT,
    );
    let hand_made = igopay_core::ForkProof {
        a: p.clone(),
        b: p.clone(),
    };
    assert_eq!(
        reg.submit_fork_proof(&hand_made, &v),
        Err(SubmitError::NotAFork)
    );
    assert!(!reg.is_blocked(&s.payer.public_key()));
}

#[test]
fn submissions_from_a_blocked_payer_still_register() {
    // A payee's claim is real even after the payer is blocked, and the evidence trail
    // should stay complete. Callers gate on is_blocked() rather than the registry
    // silently dropping data.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);

    let a = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        10_000,
        b"na",
        11,
        [0u8; 32],
        SLOT,
    );
    let b = promise(
        &s.payer,
        &s.cert,
        s.payee_b.public_key(),
        20_000,
        b"nb",
        11,
        [0u8; 32],
        SLOT,
    );
    reg.submit(&a, &v).unwrap();
    reg.submit(&b, &v).unwrap(); // blocks the payer
    assert!(reg.is_blocked(&s.payer.public_key()));

    // A later, honest promise at seq 12 from the same payer still registers.
    let c = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        3_000,
        b"nc",
        12,
        a.body_digest(),
        1600,
    );
    assert!(matches!(
        reg.submit(&c, &v),
        Ok(Submission::Accepted { .. })
    ));
    assert_eq!(reg.highest_seq(&s.payer.public_key()), Some(12));
}

#[test]
fn digests_for_payer_are_seq_ordered() {
    // Reconciliation aid: the issuer's record of a payer's chain, in chain order.
    let s = scene();
    let v = P256Verifier;
    let mut reg = registry(&s);
    let p1 = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        1_000,
        b"n1",
        11,
        [0u8; 32],
        SLOT,
    );
    let p2 = promise(
        &s.payer,
        &s.cert,
        s.payee_a.public_key(),
        2_000,
        b"n2",
        12,
        p1.body_digest(),
        1600,
    );
    // Submit out of order to prove ordering comes from the key, not insertion order.
    reg.submit(&p2, &v).unwrap();
    reg.submit(&p1, &v).unwrap();

    let digests = reg.digests_for_payer(&s.payer.public_key());
    assert_eq!(
        digests,
        vec![(11, p1.body_digest()), (12, p2.body_digest())]
    );
}
