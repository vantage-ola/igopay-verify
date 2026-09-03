//! Property: ANY two promises from the same payer with equal `seq` and different
//! signed bodies yield a fork proof that independently verifies. This is the Phase 1
//! exit criterion (`07-build-plan.md` §3): a double spend is always undeniable.
//!
//! There is no proptest dependency in this crate (offline, minimal deps), so the
//! "property" is exercised by an exhaustive sweep over a grid of body-varying
//! fields. Every distinct pair that differs in body must produce a valid proof.
//!
//! Two granularities:
//!   * a **small** grid runs by default (fast, keeps the local `cargo test` loop
//!     snappy — every pair still does two real P-256 verifications);
//!   * the **full** 3,240-pair sweep is `#[ignore]`d because it takes ~90 s. CI runs
//!     it explicitly with `cargo test -- --include-ignored`, so the exit criterion is
//!     still exercised on every push without slowing day-to-day development.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::verify::{detect_fork, verify_fork_proof};
use igopay_core::{Certificate, P256Verifier, Promise, SlotGrant};

fn base_cert(issuer: &TestSigner, payer: &TestSigner) -> Certificate {
    let grant = SlotGrant {
        from: 1000,
        to: 1000 + 2880,
        granularity_secs: 60,
    };
    make_certificate(issuer, payer, "adunni", 2, 1_000_000, grant, 0, 0, u64::MAX)
}

/// Build a promise at a fixed seq whose BODY varies with the inputs.
fn variant(
    payer: &TestSigner,
    cert: &Certificate,
    payee_seed: u8,
    amount: u64,
    nonce: &[u8],
    slot: u64,
) -> Promise {
    let payee = TestSigner::from_seed(payee_seed);
    make_promise(
        payer,
        cert,
        payee.public_key(),
        amount,
        "NGN",
        nonce,
        42, // FIXED seq for every variant — the fork condition
        [0u8; 32],
        slot,
    )
}

/// Run the exhaustive pairwise sweep over the given grid and return the number of
/// pairs checked. Every distinct pair (all pairs here, since the grid is built to
/// contain only distinct bodies) must yield a fork proof that independently verifies.
fn run_sweep(payees: &[u8], amounts: &[u64], nonces: &[&[u8]], slots: &[u64]) -> u64 {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let cert = base_cert(&issuer, &payer);
    let v = P256Verifier;

    let mut promises = Vec::new();
    for &pe in payees {
        for &am in amounts {
            for &no in nonces {
                for &sl in slots {
                    promises.push(variant(&payer, &cert, pe, am, no, sl));
                }
            }
        }
    }

    let mut checked_pairs = 0u64;
    for i in 0..promises.len() {
        for j in (i + 1)..promises.len() {
            let a = &promises[i];
            let b = &promises[j];
            // Every pair has the same seq by construction, and every promise differs
            // in at least one body field, so all bodies are distinct.
            assert_ne!(
                a.body_digest(),
                b.body_digest(),
                "grid should only contain distinct bodies"
            );
            let proof = detect_fork(a, b).expect("distinct bodies + same seq => fork");
            assert!(
                verify_fork_proof(&proof, &v),
                "fork proof must independently verify for every distinct pair"
            );
            checked_pairs += 1;
        }
    }
    checked_pairs
}

#[test]
fn small_grid_distinct_bodies_yield_valid_fork_proofs() {
    // Fast default: 2×2×2×2 = 16 variants -> 16*15/2 = 120 pairs. Enough to exercise
    // the property on the common loop; the full sweep below covers the wide grid.
    let payees = [3u8, 4];
    let amounts = [1_000u64, 2_000];
    let nonces: [&[u8]; 2] = [b"n1", b"n2"];
    let slots = [1100u64, 1200];
    let checked = run_sweep(&payees, &amounts, &nonces, &slots);
    assert_eq!(checked, 120);
}

#[test]
#[ignore = "full 3,240-pair sweep (~90s); run in CI with --include-ignored"]
fn any_two_distinct_bodies_same_seq_yield_valid_fork_proof() {
    // The full exit-criterion sweep: 81 variants -> 81*80/2 = 3240 pairs, all forks.
    let payees = [3u8, 4, 5];
    let amounts = [1_000u64, 2_000, 3_000];
    let nonces: [&[u8]; 3] = [b"n1", b"n2", b"n3"];
    let slots = [1100u64, 1200, 1300];
    let checked = run_sweep(&payees, &amounts, &nonces, &slots);
    assert_eq!(checked, 3240);
}

#[test]
fn identical_bodies_never_produce_a_fork() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let cert = base_cert(&issuer, &payer);
    let p = variant(&payer, &cert, 3, 1_000, b"n1", 1100);
    // Re-encode/re-decode to get an independent but byte-identical copy.
    let q = Promise::from_bytes(&p.encode()).unwrap();
    assert!(detect_fork(&p, &q).is_none());
}
