//! Cost measurement, not an assertion.
//!
//! The question this answers: can a payee afford to re-verify the issuer's signature on
//! the block list **on every payment**, instead of verifying once at install and then
//! trusting its own storage? Trusting storage is cheaper but adds an assumption; the
//! stateless option is only worth choosing if it is actually affordable on cheap
//! hardware.
//!
//! `#[ignore]`d because timings make a poor CI gate. Run it deliberately:
//!
//! ```text
//! CARGO_HOME="$PWD/.cargo-home" CARGO_TARGET_DIR="$PWD/target" \
//!   cargo test --release --test cost_probe -- --ignored --nocapture
//! ```
//!
//! Measured on the development host (release build, pure-Rust `p256`, no assembly):
//!
//! ```text
//! promise verification (2 ECDSA):           586 us   baseline
//! blocklist decode+verify+query    1,000:   295 us   0.50x   (10 KB)
//! blocklist decode+verify+query   10,000:   332 us   0.57x   (23 KB)
//! blocklist decode+verify+query  100,000:   753 us   1.29x   (155 KB)
//! ```
//!
//! Two things read off those numbers. Re-verification costs a *fraction* of the work a
//! payment already does, so the stateless design is affordable — a phone is perhaps
//! 10–30x slower than this host, putting the block-list check in the low tens of
//! milliseconds against a QR camera scan that takes hundreds. And the cost is dominated
//! by **hashing the list body**, not by the signature: at 1k–10k entries the check is
//! cheaper than verifying a promise (one ECDSA verify against the promise's two), and
//! only at 100k blocked payers does the SHA-256 over 155 KB begin to dominate.
//!
//! These are host numbers, not device numbers. The on-device figure is still unmeasured.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::{PubKeyBytes, Signer};
use igopay_core::{
    verify_promise, BlockList, FixedClock, P256Verifier, SignedBlockList, SlotGrant, VerifyContext,
};
use std::hint::black_box;
use std::time::Instant;

fn key(n: u32) -> PubKeyBytes {
    let mut k = [0u8; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_be_bytes());
    k
}

#[test]
#[ignore = "timing measurement; run with --ignored --nocapture"]
fn cost_probe() {
    const ROUNDS: u32 = 300;

    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let grant = SlotGrant {
        from: 1_000,
        to: 1_000 + 2_880,
        granularity_secs: 60,
    };
    let cert = make_certificate(&issuer, &payer, "adunni", 2, 50_000, grant, 0, 0, 100_000);
    let promise = make_promise(
        &payer,
        &cert,
        payee.public_key(),
        1_000,
        "NGN",
        b"nonce",
        1,
        [0u8; 32],
        1_060,
    );

    let verifier = P256Verifier;
    let clock = FixedClock(1_500);
    let empty = BlockList::new(4_096, 4);

    let t = Instant::now();
    for _ in 0..ROUNDS {
        let ctx = VerifyContext {
            issuer_pubkey: &issuer.public_key(),
            my_pubkey: &payee.public_key(),
            expected_nonce: b"nonce",
            block_list: &empty,
            verifier: &verifier,
            clock: &clock,
            known_head: None,
        };
        black_box(verify_promise(&promise, &ctx).expect("accepted"));
    }
    let promise_us = t.elapsed().as_micros() as f64 / ROUNDS as f64;
    println!("promise verification (2 ECDSA):        {promise_us:>8.1} us   baseline");

    for blocked in [1_000u32, 10_000, 100_000] {
        let mut list = BlockList::sized_for(blocked as usize, 12);
        for n in 0..blocked {
            list.insert(&key(n));
        }
        for n in blocked - 256..blocked {
            list.insert_recent(key(n));
        }
        let mut doc = list.to_unsigned(1, 0, 86_400);
        doc.sig_issuer = issuer.sign_prehash(&doc.body_digest());
        let bytes = doc.encode();

        let t = Instant::now();
        for _ in 0..ROUNDS {
            let decoded = SignedBlockList::decode(&bytes).expect("decodes");
            let opened = decoded
                .verify_and_open(&issuer.public_key(), &verifier, None)
                .expect("installs");
            black_box(opened.contains(&key(7)));
        }
        let us = t.elapsed().as_micros() as f64 / ROUNDS as f64;
        println!(
            "blocklist decode+verify+query {blocked:>7}: {us:>8.1} us   {:>5.2}x  ({} KB)",
            us / promise_us,
            bytes.len() / 1024
        );
    }
}
