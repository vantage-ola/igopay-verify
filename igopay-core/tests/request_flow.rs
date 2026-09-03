//! Payee request-flow tests (`src/types.rs` `PaymentRequest`, `verify.rs`
//! `verify_promise_for_request`).
//!
//! The payee generates a `PaymentRequest` (payee key + amount + fresh nonce), shows
//! it as a QR, the payer scans it and returns a signed promise, and the payee
//! verifies that promise AGAINST THE REQUEST. These tests cover the round-trip and
//! the request-specific checks (amount/currency must match what was asked) on top of
//! the full offline verification.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::verify::{verify_promise_for_request, VerifyError};
use igopay_core::{
    BlockList, Certificate, FixedClock, P256Verifier, PaymentRequest, Promise, SlotGrant,
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

fn request(s: &Scene, amount: u64, currency: &str, nonce: &[u8]) -> PaymentRequest {
    PaymentRequest {
        payee_pubkey: s.payee.public_key(),
        amount,
        currency: currency.into(),
        nonce: nonce.to_vec(),
    }
}

/// A promise that answers `req` honestly: bound to the request's payee/nonce, paying
/// the requested amount/currency.
fn answering_promise(s: &Scene, req: &PaymentRequest, seq: u64, slot: u64) -> Promise {
    make_promise(
        &s.payer,
        &s.cert,
        req.payee_pubkey,
        req.amount,
        &req.currency,
        &req.nonce,
        seq,
        [0u8; 32],
        slot,
    )
}

#[test]
fn payment_request_roundtrips() {
    let s = scene();
    let req = request(&s, 10_000, "NGN", b"fresh-nonce-01");
    let bytes = req.encode();
    let decoded = PaymentRequest::from_bytes(&bytes).expect("decode request");
    assert_eq!(decoded, req);
    // Canonical: re-encoding is byte-identical.
    assert_eq!(decoded.encode(), bytes);
}

#[test]
fn honest_promise_for_request_accepts() {
    let s = scene();
    let req = request(&s, 10_000, "NGN", b"fresh-nonce-01");
    let promise = answering_promise(&s, &req, 11, 1540);

    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let accepted = verify_promise_for_request(
        &promise,
        &req,
        &s.issuer.public_key(),
        &bl,
        &v,
        &clock,
        None,
    )
    .expect("honest promise answering the request must accept");
    assert_eq!(accepted.exposure.promises_since_issue, 1);
}

#[test]
fn wrong_amount_rejected() {
    // Payer signs a promise for LESS than requested. verify_promise alone would pass
    // it (it is within the cert cap); the request check catches the mismatch.
    let s = scene();
    let req = request(&s, 10_000, "NGN", b"fresh-nonce-01");
    let promise = make_promise(
        &s.payer,
        &s.cert,
        req.payee_pubkey,
        9_000, // asked for 10_000
        &req.currency,
        &req.nonce,
        11,
        [0u8; 32],
        1540,
    );
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    assert_eq!(
        verify_promise_for_request(
            &promise,
            &req,
            &s.issuer.public_key(),
            &bl,
            &v,
            &clock,
            None
        ),
        Err(VerifyError::AmountMismatch {
            requested: 10_000,
            got: 9_000,
        })
    );
}

#[test]
fn wrong_currency_rejected() {
    let s = scene();
    let req = request(&s, 10_000, "NGN", b"fresh-nonce-01");
    let promise = make_promise(
        &s.payer,
        &s.cert,
        req.payee_pubkey,
        10_000,
        "USD", // requested NGN
        &req.nonce,
        11,
        [0u8; 32],
        1540,
    );
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    assert_eq!(
        verify_promise_for_request(
            &promise,
            &req,
            &s.issuer.public_key(),
            &bl,
            &v,
            &clock,
            None
        ),
        Err(VerifyError::CurrencyMismatch)
    );
}

#[test]
fn promise_answering_a_different_nonce_rejected() {
    // A replayed promise made against a STALE request (old nonce) must be rejected
    // when verified against the fresh request — this is the replay defence, threaded
    // through the request rather than a raw context.
    let s = scene();
    let fresh = request(&s, 10_000, "NGN", b"fresh-nonce-02");
    // The promise was built for a previous request with a different nonce.
    let stale_promise = make_promise(
        &s.payer,
        &s.cert,
        fresh.payee_pubkey,
        10_000,
        "NGN",
        b"old-nonce-01",
        11,
        [0u8; 32],
        1540,
    );
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    assert_eq!(
        verify_promise_for_request(
            &stale_promise,
            &fresh,
            &s.issuer.public_key(),
            &bl,
            &v,
            &clock,
            None
        ),
        Err(VerifyError::WrongNonce)
    );
}

#[test]
fn promise_bound_to_a_different_payee_rejected() {
    // The request carries payee A's key, but the promise is bound to payee B. Verified
    // against A's request, it must be rejected as WrongPayee (relay defence).
    let s = scene();
    let req = request(&s, 10_000, "NGN", b"fresh-nonce-03");
    let other_payee = TestSigner::from_seed(9);
    let promise = make_promise(
        &s.payer,
        &s.cert,
        other_payee.public_key(), // not req.payee_pubkey
        10_000,
        "NGN",
        &req.nonce,
        11,
        [0u8; 32],
        1540,
    );
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    assert_eq!(
        verify_promise_for_request(
            &promise,
            &req,
            &s.issuer.public_key(),
            &bl,
            &v,
            &clock,
            None
        ),
        Err(VerifyError::WrongPayee)
    );
}
