//! End-to-end tests for the artefact builders (`src/build.rs`).
//!
//! The point of the builders is that anything they produce verifies BY
//! CONSTRUCTION — the payer/issuer side and the payee side agree on the canonical
//! body digest — and that a chain of promises links correctly. These tests assert
//! exactly that against the real `verify_promise`, using the deterministic
//! `TestSigner` as a stand-in for a hardware Keystore/Enclave signer.

mod common;

use common::TestSigner;
use igopay_core::verify::{verify_promise, ChainHead, VerifyContext, VerifyError};
use igopay_core::{
    build_certificate, sign_promise_body, BlockList, FixedClock, P256Verifier, PaymentDetails,
    Promise, PromiseBuilder, SlotGrant,
};

const NOW: u64 = 1600;

fn grant() -> SlotGrant {
    SlotGrant {
        from: 1000,
        to: 1000 + 2880,
        granularity_secs: 60,
    }
}

/// A certificate valid across the whole scene, built THROUGH `build_certificate`.
fn issued_cert(issuer: &TestSigner, payer: &TestSigner) -> igopay_core::Certificate {
    build_certificate(
        issuer,
        {
            use igopay_core::crypto::Signer;
            payer.public_key()
        },
        "adunni".into(),
        2,
        50_000,
        grant(),
        10,
        0,
        100_000,
    )
}

#[test]
fn built_certificate_verifies_against_issuer_key() {
    use igopay_core::crypto::{Signer, Verifier};
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let cert = issued_cert(&issuer, &payer);
    // The issuer signature must verify against the issuer's own key, over the
    // canonical body digest the verifier recomputes.
    let v = P256Verifier;
    assert!(v
        .verify_prehash(&issuer.public_key(), &cert.body_digest(), &cert.sig_issuer)
        .is_ok());
}

#[test]
fn built_promise_verifies_by_construction() {
    use igopay_core::crypto::Signer;
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let cert = issued_cert(&issuer, &payer);

    let mut builder = PromiseBuilder::fresh(&payer, cert);
    // fresh() starts at seq_at_issue + 1 = 11.
    assert_eq!(builder.next_seq(), 11);

    let nonce = b"payee-nonce-xyz".to_vec();
    let promise = builder.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 10_000,
        currency: "NGN".into(),
        nonce: nonce.clone(),
        slot: 1540,
    });

    let issuer_pk = issuer.public_key();
    let payee_pk = payee.public_key();
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let ctx = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: &nonce,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: None,
    };
    let accepted = verify_promise(&promise, &ctx).expect("built promise must verify");
    assert_eq!(accepted.exposure.promises_since_issue, 1);
    // The builder advanced its state for the next promise.
    assert_eq!(builder.next_seq(), 12);
    assert_eq!(builder.current_head(), promise.body_digest());
}

#[test]
fn builder_chain_links_across_promises() {
    use igopay_core::crypto::Signer;
    // Two promises to the SAME payee (first-seen then immediate successor): the
    // second must chain-link to the first via prev_hash, and the verifier's
    // ChainHead check must accept it.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let cert = issued_cert(&issuer, &payer);

    let mut builder = PromiseBuilder::fresh(&payer, cert);
    let nonce1 = b"nonce-1".to_vec();
    let p1 = builder.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 5_000,
        currency: "NGN".into(),
        nonce: nonce1.clone(),
        slot: 1540,
    });
    let nonce2 = b"nonce-2".to_vec();
    let p2 = builder.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 7_000,
        currency: "NGN".into(),
        nonce: nonce2.clone(),
        slot: 1600,
    });

    // p2 is the immediate successor of p1.
    assert_eq!(p2.seq, p1.seq + 1);
    // Its prev_hash must be p1's body digest — the hash link.
    assert_eq!(p2.prev_hash, p1.body_digest());

    let issuer_pk = issuer.public_key();
    let payee_pk = payee.public_key();
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);

    // Accept p1 with no prior head, capturing the new head.
    let ctx1 = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: &nonce1,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: None,
    };
    let accepted1 = verify_promise(&p1, &ctx1).expect("p1 accepts");

    // Now accept p2 with p1's head as known_head: the prev_hash link is asserted and
    // must hold.
    let ctx2 = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: &nonce2,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: Some(accepted1.new_head),
    };
    let accepted2 = verify_promise(&p2, &ctx2).expect("linked successor accepts");
    assert_eq!(accepted2.exposure.promises_since_issue, 2);
}

#[test]
fn builder_with_broken_chain_state_is_rejected() {
    use igopay_core::crypto::Signer;
    // Sanity that the LINK actually matters: if a payee holds p1's head but is handed
    // a p2' whose prev_hash does NOT match (built from a separate genesis builder),
    // verification must reject it as a broken chain.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let cert = issued_cert(&issuer, &payer);

    let mut builder_a = PromiseBuilder::fresh(&payer, cert.clone());
    let nonce1 = b"nonce-1".to_vec();
    let p1 = builder_a.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 5_000,
        currency: "NGN".into(),
        nonce: nonce1.clone(),
        slot: 1540,
    });

    // A DIFFERENT builder starting fresh: its seq-12 promise carries the genesis
    // (all-zero) prev_hash, which will not match p1's body digest.
    let mut builder_b = PromiseBuilder::new(&payer, cert, 12, [0u8; 32]);
    let nonce2 = b"nonce-2".to_vec();
    let p2_bad = builder_b.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 7_000,
        currency: "NGN".into(),
        nonce: nonce2.clone(),
        slot: 1600,
    });

    let issuer_pk = issuer.public_key();
    let payee_pk = payee.public_key();
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let head = ChainHead {
        seq: p1.seq,
        body_digest: p1.body_digest(),
    };
    let ctx = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: &nonce2,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: Some(head),
    };
    assert!(matches!(
        verify_promise(&p2_bad, &ctx),
        Err(VerifyError::PrevHashMismatch { .. })
    ));
}

#[test]
fn sign_promise_body_matches_builder_signature() {
    use igopay_core::crypto::Signer;
    // The free-function signing helper must produce the same signature the builder
    // embeds, so callers managing their own chain state get an identical result.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let cert = issued_cert(&issuer, &payer);

    let mut builder = PromiseBuilder::fresh(&payer, cert.clone());
    let nonce = b"n".to_vec();
    let built = builder.sign_next(PaymentDetails {
        payee_pubkey: payee.public_key(),
        amount: 1_000,
        currency: "NGN".into(),
        nonce: nonce.clone(),
        slot: 1540,
    });

    // Rebuild the same promise unsigned and sign it via the free function.
    let mut manual = Promise {
        payer_cert: cert,
        payee_pubkey: payee.public_key(),
        amount: 1_000,
        currency: "NGN".into(),
        nonce,
        seq: 11,
        prev_hash: [0u8; 32],
        slot: 1540,
        sig_payer: [0u8; 64],
    };
    manual.sig_payer = sign_promise_body(&payer, &manual);

    // ECDSA with the deterministic TestSigner is deterministic, so the signatures
    // match exactly and the two promises are byte-identical.
    assert_eq!(manual, built);
    assert_eq!(manual.encode(), built.encode());
}
