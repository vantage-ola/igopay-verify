//! Adversarial test vectors — first-class artefacts (`07-build-plan.md` §3 Phase 1).
//!
//! Each test constructs a specific attack against the offline verification check
//! list and asserts the core rejects it with the right error, or (for the honest
//! path) accepts it. The Phase 1 exit criterion — "a double spend produces an
//! undeniable artefact" — is the fork tests plus the property test in
//! `fork_property.rs`.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::{PubKeyBytes, Signer};
use igopay_core::verify::{
    detect_fork, verify_fork_proof, verify_promise, ChainHead, VerifyContext, VerifyError,
};
use igopay_core::{BlockList, Certificate, FixedClock, P256Verifier, Promise, SlotGrant};

const CURRENCY: &str = "NGN";

// A standard scene: issuer, payer, payee, a valid certificate, and a payee-issued
// nonce. Slot window [1000, 3880] at 60-s granularity (aligned slots 1000, 1060,
// … 3880); "now" is 1600. Honest promises name an aligned, non-future slot.
struct Scene {
    issuer: TestSigner,
    payer: TestSigner,
    payee: TestSigner,
    issuer_pk: PubKeyBytes,
    payee_pk: PubKeyBytes,
    cert: Certificate,
    nonce: Vec<u8>,
    now: u64,
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
    // Certificate valid across the whole scene: window [0, 100000] comfortably
    // brackets "now" = 1600. Cert-validity tests below use their own windows.
    let cert = make_certificate(&issuer, &payer, "adunni", 2, 50_000, grant, 10, 0, 100_000);
    let issuer_pk = issuer.public_key();
    let payee_pk = payee.public_key();
    Scene {
        issuer,
        payer,
        payee,
        issuer_pk,
        payee_pk,
        cert,
        nonce: b"payee-nonce-xyz".to_vec(),
        now: 1600,
    }
}

fn ctx<'a>(
    s: &'a Scene,
    verifier: &'a P256Verifier,
    clock: &'a FixedClock,
    block_list: &'a BlockList,
    known_head: Option<ChainHead>,
) -> VerifyContext<'a, P256Verifier, FixedClock> {
    VerifyContext {
        issuer_pubkey: &s.issuer_pk,
        my_pubkey: &s.payee_pk,
        expected_nonce: &s.nonce,
        block_list,
        verifier,
        clock,
        known_head,
    }
}

fn honest_promise(s: &Scene) -> Promise {
    make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1540, // aligned: 1000 + 9*60, and <= now (1600)
    )
}

#[test]
fn honest_promise_verifies() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = honest_promise(&s);
    let accepted = verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).expect("accept");
    // seq 11, seq_at_issue 10 -> one promise since issue.
    assert_eq!(accepted.exposure.promises_since_issue, 1);
}

#[test]
fn wrong_payee_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let attacker = TestSigner::from_seed(9);
    // Payer signs a promise bound to the WRONG payee (relay/substitution attempt).
    let p = make_promise(
        &s.payer,
        &s.cert,
        attacker.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1500,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::WrongPayee)
    );
}

#[test]
fn replayed_nonce_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        b"a-different-old-nonce",
        11,
        [0u8; 32],
        1500,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::WrongNonce)
    );
}

#[test]
fn over_cap_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        50_001, // cap is 50_000
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1500,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::OverCap)
    );
}

#[test]
fn slot_before_grant_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        999, // grant.from is 1000
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::SlotOutsideGrant)
    );
}

#[test]
fn slot_in_future_rejected() {
    let s = scene();
    let v = P256Verifier;
    // Clock says 1500; a slot at 1600 is well beyond the ±5 s skew tolerance, and
    // still inside the grant window, so it must be rejected as future-dated.
    let clock = FixedClock(1500);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1600,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::SlotInFuture)
    );
}

#[test]
fn slot_within_skew_accepted() {
    let s = scene();
    let v = P256Verifier;
    // Aligned slot 1600 with clock 1597 is +3 s, inside the ±5 s tolerance.
    let clock = FixedClock(1597);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1600,
    );
    assert!(verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok());
}

#[test]
fn slot_misaligned_rejected() {
    // In-window but off the 60-s boundary: 1530 = 1000 + 530, not a multiple of 60.
    // B10 slots are a fixed namespace, so an off-grid slot is malformed.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1530,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::SlotMisaligned {
            from: 1000,
            granularity_secs: 60,
            got: 1530,
        })
    );
}

// The pair below is the bug `tools/ffi-probe` hit on a real handset, and its fix.
//
// B10's slot lattice is anchored at `grant.from` — the second the issuer signed the
// certificate — not at a clock boundary. `scene()`'s grant starts at 1000 with 60-s
// granularity, and 1000 is not a multiple of 60, so the two disagree. A payer that
// names "the current minute" the obvious way produces a slot every payee refuses.
// `SlotGrant::slot_at` exists so no caller has to know that.

#[test]
fn a_clock_floored_slot_is_refused() {
    let s = scene();
    let v = P256Verifier;
    // 1010 is inside the first 60-s period of the grant. Flooring it to a clock
    // boundary gives 960, which is BELOW the anchor at 1000 — so the failure is
    // `SlotOutsideGrant`, and the promise never even reaches the alignment check.
    let now = 1010;
    let clock_floored = now / 60 * 60;
    assert_eq!(clock_floored, 960);
    let clock = FixedClock(now);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        clock_floored,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::SlotOutsideGrant)
    );
}

#[test]
fn the_slot_slot_at_derives_is_accepted_at_the_same_instant() {
    // Same payer, same certificate, same second as the test above. The ONLY difference
    // is where the slot came from — which is the whole point of having the method.
    let s = scene();
    let v = P256Verifier;
    let now = 1010;
    let clock = FixedClock(now);
    let bl = BlockList::new(4096, 4);
    let slot = s.cert.slot_grant.slot_at(now).expect("in-grant instant");
    assert_eq!(slot, 1000);
    let p = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        slot,
    );
    assert!(verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok());
}

#[test]
fn slot_at_is_accepted_at_every_boundary_of_the_grant() {
    // The documented guarantee, checked against the real verifier rather than restated:
    // whatever `slot_at` returns, `verify_promise` accepts at that same instant. The
    // instants are the ones where an off-by-one would show — the anchor, either side of
    // a period edge, and both ends of the window.
    let s = scene();
    let v = P256Verifier;
    let bl = BlockList::new(4096, 4);
    let g = &s.cert.slot_grant;
    for now in [
        g.from,
        g.from + 1,
        g.from + 59,
        g.from + 60,
        g.from + 61,
        (g.from + g.to) / 2,
        g.to - 1,
        g.to,
    ] {
        let slot = g.slot_at(now).unwrap_or_else(|| panic!("no slot at {now}"));
        let p = make_promise(
            &s.payer,
            &s.cert,
            s.payee.public_key(),
            10_000,
            CURRENCY,
            &s.nonce,
            11,
            [0u8; 32],
            slot,
        );
        let clock = FixedClock(now);
        assert!(
            verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok(),
            "slot {slot} derived at {now} was refused"
        );
    }
}

#[test]
fn slot_at_never_derives_a_slot_the_verifier_would_refuse() {
    // The same guarantee as a sweep over every second of the grant and a margin either
    // side of it. Signing 2881 promises would make this a slow test for no extra
    // coverage, so this asserts the verifier's four slot predicates directly — they are
    // the checks a promise carrying this slot would face.
    let g = SlotGrant {
        from: 1000,
        to: 1000 + 2880,
        granularity_secs: 60,
    };
    for now in (g.from - 100)..=(g.to + 100) {
        match g.slot_at(now) {
            None => assert!(
                now < g.from || now > g.to,
                "no slot inside the grant at {now}"
            ),
            Some(slot) => {
                assert!(slot >= g.from, "slot {slot} below the anchor");
                assert!(slot <= g.to, "slot {slot} past the window");
                assert_eq!(
                    (slot - g.from) % g.granularity_secs,
                    0,
                    "slot {slot} off-lattice"
                );
                assert!(slot <= now, "slot {slot} is future-dated at {now}");
            }
        }
    }
}

#[test]
fn seq_replay_rejected_when_known() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let p = honest_promise(&s); // seq 11
                                // We already accepted seq 11 from this payer (any body_digest; the seq floor is
                                // what trips first here).
    let head = ChainHead {
        seq: 11,
        body_digest: [0u8; 32],
    };
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, Some(head))),
        Err(VerifyError::SeqDiscontinuity {
            expected_min: 12,
            got: 11
        })
    );
}

#[test]
fn immediate_successor_with_good_prev_hash_accepted() {
    // A payee that accepted promise #11 then sees #12 whose prev_hash links to #11.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);

    let first = honest_promise(&s); // seq 11
    let head = ChainHead {
        seq: first.seq,
        body_digest: first.body_digest(),
    };
    // Build #12 correctly linked to #11.
    let second = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        5_000,
        CURRENCY,
        &s.nonce,
        12,
        first.body_digest(), // prev_hash links to #11
        1600,
    );
    let accepted =
        verify_promise(&second, &ctx(&s, &v, &clock, &bl, Some(head))).expect("linked ok");
    assert_eq!(accepted.new_head.seq, 12);
    assert_eq!(accepted.new_head.body_digest, second.body_digest());
}

#[test]
fn immediate_successor_with_broken_prev_hash_rejected() {
    // #12 claims to follow #11 but its prev_hash points nowhere real: chain break.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);

    let first = honest_promise(&s); // seq 11
    let head = ChainHead {
        seq: first.seq,
        body_digest: first.body_digest(),
    };
    let bogus_prev = [0x99u8; 32];
    let second = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        5_000,
        CURRENCY,
        &s.nonce,
        12,
        bogus_prev, // does NOT link to #11
        1600,
    );
    assert_eq!(
        verify_promise(&second, &ctx(&s, &v, &clock, &bl, Some(head))),
        Err(VerifyError::PrevHashMismatch {
            expected: first.body_digest(),
            got: bogus_prev,
        })
    );
}

#[test]
fn seq_gap_does_not_assert_prev_hash() {
    // #14 after a known #11 is a gap (promises #12,#13 went to other payees we never
    // saw). We cannot check the intervening link offline, so prev_hash is NOT
    // asserted; the promise is accepted and the seq floor still held.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);

    let first = honest_promise(&s); // seq 11
    let head = ChainHead {
        seq: first.seq,
        body_digest: first.body_digest(),
    };
    let later = make_promise(
        &s.payer,
        &s.cert,
        s.payee.public_key(),
        5_000,
        CURRENCY,
        &s.nonce,
        14,           // gap over 12, 13
        [0x33u8; 32], // unrelated prev_hash — not asserted across a gap
        1600,
    );
    let accepted =
        verify_promise(&later, &ctx(&s, &v, &clock, &bl, Some(head))).expect("gap accepted");
    assert_eq!(accepted.new_head.seq, 14);
}

#[test]
fn blocked_payer_in_the_exact_set_is_rejected_as_certain() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let mut bl = BlockList::new(4096, 4);
    bl.insert_recent(s.payer.public_key());
    let p = honest_promise(&s);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::BlockedPayer)
    );
}

#[test]
fn blocked_payer_only_in_the_filter_is_rejected_as_probable() {
    // A filter-only hit carries the Bloom false-positive rate, so it must not be
    // reported as a certainty — a fraction of honest payers would otherwise be told
    // they are cheats with no recourse.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let mut bl = BlockList::new(4096, 4);
    bl.insert(&s.payer.public_key());
    let p = honest_promise(&s);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::BlockedPayerProbable)
    );
}

#[test]
fn a_payer_on_neither_list_is_accepted() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let mut bl = BlockList::new(4096, 4);
    bl.insert(&[0x02u8; 33]); // somebody else entirely
    bl.insert_recent([0x03u8; 33]);
    let p = honest_promise(&s);
    assert!(verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok());
}

#[test]
fn forged_issuer_signature_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let mut p = honest_promise(&s);
    // Tamper with the certificate body AFTER issuance: raise the cap. sig_issuer no
    // longer matches the body.
    p.payer_cert.per_payment_cap = 10_000_000;
    // Re-sign the promise so sig_payer is valid over the tampered cert; only the
    // issuer signature should now fail.
    p.sig_payer = s.payer.sign_prehash(&p.body_digest());
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::BadIssuerSignature)
    );
}

#[test]
fn forged_payer_signature_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let mut p = honest_promise(&s);
    // Flip a byte in the amount, leaving the signature stale.
    p.amount = 20_000;
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::BadPayerSignature)
    );
}

#[test]
fn high_s_signature_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    let mut p = honest_promise(&s);
    // Malleate the (valid, low-S) payer signature into its high-S counterpart. It
    // still verifies mathematically but must be rejected as malleable.
    p.sig_payer = TestSigner::malleate(&p.sig_payer);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::MalleableSignature)
    );
}

#[test]
fn truncated_payload_rejected_by_decoder() {
    let s = scene();
    let p = honest_promise(&s);
    let bytes = p.encode();
    // Chop the last byte — the decoder must not accept a partial promise.
    let truncated = &bytes[..bytes.len() - 1];
    assert!(Promise::from_bytes(truncated).is_err());
}

#[test]
fn trailing_bytes_rejected_by_decoder() {
    let s = scene();
    let p = honest_promise(&s);
    let mut bytes = p.encode();
    bytes.push(0x00); // extra byte after a complete promise
    assert!(Promise::from_bytes(&bytes).is_err());
}

#[test]
fn roundtrip_encode_decode_is_identity() {
    let s = scene();
    let p = honest_promise(&s);
    let bytes = p.encode();
    let decoded = Promise::from_bytes(&bytes).expect("decode");
    assert_eq!(decoded, p);
    // And re-encoding is byte-identical (canonical form is stable).
    assert_eq!(decoded.encode(), bytes);
}

// ----------------------------- fork detection -----------------------------

#[test]
fn double_spend_yields_valid_fork_proof() {
    let s = scene();
    let v = P256Verifier;
    // Same payer, same seq, two DIFFERENT payees/amounts: a genuine double spend.
    let payee_b = TestSigner::from_seed(7);
    let a = honest_promise(&s); // seq 11 to payee (seed 3)
    let b = make_promise(
        &s.payer,
        &s.cert,
        payee_b.public_key(),
        25_000,
        CURRENCY,
        b"other-nonce",
        11, // SAME seq
        [0u8; 32],
        1500,
    );
    let proof = detect_fork(&a, &b).expect("fork detected");
    assert!(
        verify_fork_proof(&proof, &v),
        "proof must independently verify"
    );
}

#[test]
fn identical_duplicate_is_not_a_fork() {
    let s = scene();
    let a = honest_promise(&s);
    let b = a.clone();
    assert!(detect_fork(&a, &b).is_none(), "a replay is not a fork");
}

#[test]
fn different_payers_same_seq_is_not_a_fork() {
    let s = scene();
    // A different payer entirely, with their own certificate.
    let issuer = &s.issuer;
    let payer2 = TestSigner::from_seed(8);
    let grant = SlotGrant {
        from: 1000,
        to: 3880,
        granularity_secs: 60,
    };
    let cert2 = make_certificate(issuer, &payer2, "chidi", 2, 50_000, grant, 10, 0, 100_000);
    let a = honest_promise(&s);
    let b = make_promise(
        &payer2,
        &cert2,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1500,
    );
    assert!(detect_fork(&a, &b).is_none());
}

#[test]
fn fabricated_fork_proof_with_bad_signature_rejected() {
    let s = scene();
    let v = P256Verifier;
    let payee_b = TestSigner::from_seed(7);
    let a = honest_promise(&s);
    let mut b = make_promise(
        &s.payer,
        &s.cert,
        payee_b.public_key(),
        25_000,
        CURRENCY,
        b"other-nonce",
        11,
        [0u8; 32],
        1500,
    );
    // Corrupt b's signature: the pair now looks like a fork structurally but is not
    // provable, so verify_fork_proof must reject it.
    b.sig_payer = [0xABu8; 64];
    // detect_fork only checks structure (payer/seq/body), so it still builds a proof
    // object; the independent verifier is what refuses it.
    let proof = detect_fork(&a, &b).expect("structural fork");
    assert!(!verify_fork_proof(&proof, &v));
}

#[test]
fn fork_proof_roundtrips_and_still_verifies() {
    // A fork proof is portable evidence (B8): it must serialize, survive transport,
    // and independently verify on the other side byte-for-byte.
    let s = scene();
    let v = P256Verifier;
    let payee_b = TestSigner::from_seed(7);
    let a = honest_promise(&s);
    let b = make_promise(
        &s.payer,
        &s.cert,
        payee_b.public_key(),
        25_000,
        CURRENCY,
        b"other-nonce",
        11, // same seq -> fork
        [0u8; 32],
        1500,
    );
    let proof = detect_fork(&a, &b).expect("fork");
    let bytes = proof.encode();
    let decoded = igopay_core::ForkProof::from_bytes(&bytes).expect("decode proof");
    assert_eq!(decoded, proof);
    // Re-encoding is byte-identical (canonical), and the decoded proof verifies.
    assert_eq!(decoded.encode(), bytes);
    assert!(verify_fork_proof(&decoded, &v));
}

// ---------------------------------------------------------------------------
// Certificate validity window (self-revocation without an online lookup).
//
// The scene's certificate is valid over [0, 100000], which brackets now=1600, so
// every test above exercises the in-window path implicitly. These build a payer
// certificate with a custom window and assert the boundary behaviour directly.
// ---------------------------------------------------------------------------

/// Build a scene-shaped promise whose certificate carries a custom validity window.
/// The slot grant is set to exactly `[not_before, not_after]` so it always sits
/// inside the validity window (that coherence check has its own test below); the
/// promise names the aligned base slot `not_before`. The ONLY variable under test
/// is therefore the validity window vs. the clock.
fn promise_with_cert_window(s: &Scene, not_before: u64, not_after: u64) -> Promise {
    let grant = SlotGrant {
        from: not_before,
        to: not_after,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &s.issuer, &s.payer, "adunni", 2, 50_000, grant, 10, not_before, not_after,
    );
    make_promise(
        &s.payer,
        &cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        not_before, // aligned base slot (k=0), always inside the grant
    )
}

#[test]
fn cert_within_validity_window_accepted() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now); // now = 1600
    let bl = BlockList::new(4096, 4);
    // now sits strictly inside [1000, 2000].
    let p = promise_with_cert_window(&s, 1000, 2000);
    assert!(verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok());
}

#[test]
fn cert_at_window_boundaries_accepted() {
    let s = scene();
    let v = P256Verifier;
    let bl = BlockList::new(4096, 4);
    // not_before is inclusive: now == not_before is valid.
    let p = promise_with_cert_window(&s, 1600, 3000);
    let clock_nb = FixedClock(1600);
    assert!(
        verify_promise(&p, &ctx(&s, &v, &clock_nb, &bl, None)).is_ok(),
        "now == not_before must be accepted (inclusive)"
    );
    // not_after is inclusive: now == not_after is valid.
    let p2 = promise_with_cert_window(&s, 1000, 1600);
    let clock_na = FixedClock(1600);
    assert!(
        verify_promise(&p2, &ctx(&s, &v, &clock_na, &bl, None)).is_ok(),
        "now == not_after must be accepted (inclusive)"
    );
}

#[test]
fn cert_not_yet_valid_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now); // now = 1600
    let bl = BlockList::new(4096, 4);
    // Window opens at 1601, one second after now.
    let p = promise_with_cert_window(&s, 1601, 5000);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::CertNotYetValid {
            not_before: 1601,
            now: 1600,
        })
    );
}

#[test]
fn cert_expired_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now); // now = 1600
    let bl = BlockList::new(4096, 4);
    // Window closed at 1599, one second before now. This is the offline
    // self-revocation path: an expired cert stops being accepted with no network.
    let p = promise_with_cert_window(&s, 1000, 1599);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::CertExpired {
            not_after: 1599,
            now: 1600,
        })
    );
}

#[test]
fn cert_inverted_window_rejected() {
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now);
    let bl = BlockList::new(4096, 4);
    // not_after < not_before: a malformed grant the issuer should never sign. Even
    // though it is issuer-signed here, the verifier refuses it structurally.
    let p = promise_with_cert_window(&s, 2000, 1000);
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::CertWindowInverted {
            not_before: 2000,
            not_after: 1000,
        })
    );
}

#[test]
fn cert_expiry_checked_before_slot_and_cap() {
    // Ordering guard: an expired certificate is rejected as CertExpired even when the
    // promise would ALSO fail a later check (over-cap here). This proves the validity
    // window gates the whole promise, not just some fields.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(s.now); // now = 1600
    let bl = BlockList::new(4096, 4);
    // Grant fits inside the (already-closed) validity window so the coherence check
    // passes and expiry is what fires. Window [1000, 1599], grant [1000, 1540].
    let grant = SlotGrant {
        from: 1000,
        to: 1540,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &s.issuer, &s.payer, "adunni", 2, 50_000, grant, 10, 1000, 1599,
    );
    let p = make_promise(
        &s.payer,
        &cert,
        s.payee.public_key(),
        999_999, // also over cap — but expiry should fire first
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1540,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::CertExpired {
            not_after: 1599,
            now: 1600
        })
    );
}

#[test]
fn cert_with_validity_window_roundtrips() {
    // The window fields are part of the signed body, so they must survive
    // encode/decode byte-for-byte and keep the issuer signature valid.
    let s = scene();
    // Grant sits inside the validity window [1234, 5678] so the coherence check
    // (grant ⊆ validity) passes and only the roundtrip is under test.
    let grant = SlotGrant {
        from: 1234,
        to: 5678,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &s.issuer, &s.payer, "adunni", 2, 50_000, grant, 10, 1234, 5678,
    );
    let bytes = cert.encode();
    let decoded = Certificate::from_bytes(&bytes).expect("decode cert");
    assert_eq!(decoded, cert);
    assert_eq!(decoded.not_before, 1234);
    assert_eq!(decoded.not_after, 5678);
    assert_eq!(decoded.encode(), bytes);
    // And a promise carrying it still verifies end-to-end within the window.
    let v = P256Verifier;
    let clock = FixedClock(2000);
    let bl = BlockList::new(4096, 4);
    let p = make_promise(
        &s.payer,
        &decoded,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1234, // aligned base slot, inside grant and <= now
    );
    assert!(verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)).is_ok());
}

#[test]
fn cert_grant_outside_validity_rejected() {
    // Coherence check (grant ⊆ validity): the issuer granted slots [1000, 3880] but
    // the certificate is only valid over [1500, 3880]. grant.from (1000) < not_before
    // (1500), so slots exist for a period the cert is not valid over — malformed,
    // rejected structurally regardless of the clock.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(1600);
    let bl = BlockList::new(4096, 4);
    let grant = SlotGrant {
        from: 1000,
        to: 3880,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &s.issuer, &s.payer, "adunni", 2, 50_000, grant, 10, 1500, 3880,
    );
    let p = make_promise(
        &s.payer,
        &cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1600, // aligned, in-grant, non-future — but the cert itself is malformed
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::GrantOutsideValidity {
            grant_from: 1000,
            grant_to: 3880,
            not_before: 1500,
            not_after: 3880,
        })
    );
}

#[test]
fn cert_grant_to_after_validity_rejected() {
    // The other half of the coherence check: grant.to runs past not_after.
    let s = scene();
    let v = P256Verifier;
    let clock = FixedClock(1600);
    let bl = BlockList::new(4096, 4);
    let grant = SlotGrant {
        from: 1000,
        to: 5000,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &s.issuer, &s.payer, "adunni", 2, 50_000, grant, 10, 1000, 3880,
    );
    let p = make_promise(
        &s.payer,
        &cert,
        s.payee.public_key(),
        10_000,
        CURRENCY,
        &s.nonce,
        11,
        [0u8; 32],
        1600,
    );
    assert_eq!(
        verify_promise(&p, &ctx(&s, &v, &clock, &bl, None)),
        Err(VerifyError::GrantOutsideValidity {
            grant_from: 1000,
            grant_to: 5000,
            not_before: 1000,
            not_after: 3880,
        })
    );
}
