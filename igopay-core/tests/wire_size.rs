//! Wire-size check: confirms the encoded promise matches the Phase 0 measurement
//! (`09-phase0-results.md` §1: real promise ≈ 337 B, embedded certificate). This is
//! a regression guard — if a field or encoding change blows the ≤400 B QR budget,
//! this test fails loudly rather than surfacing as a scan failure in the field.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::SlotGrant;

#[test]
fn embedded_promise_is_within_qr_budget() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let grant = SlotGrant {
        from: 1_700_000_000,
        to: 1_700_172_800,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &issuer,
        &payer,
        "adunni",
        2,
        50_000,
        grant,
        10,
        1_700_000_000,
        1_700_172_800,
    );
    let promise = make_promise(
        &payer,
        &cert,
        payee.public_key(),
        10_000,
        "NGN",
        &[0u8; 12], // a 12-byte payee nonce
        11,
        [0u8; 32],
        1_700_000_600,
    );

    let size = promise.encode().len();
    // The Phase 0 budget is ≤400 B; the measured figure was ~337 B. This build's
    // canonical map encoding lands at ~320 B (small integer amounts/slots/validity
    // fields encode in 1–5 bytes rather than the fixed-width mock used in §1),
    // comfortably under the QR budget. Assert both the hard budget and a sane band
    // so a field/encoding change that bloats the promise fails here, not at a
    // scanner in the field.
    assert!(
        size <= 400,
        "promise {} B exceeds the 400 B QR budget (Phase 0 §1)",
        size
    );
    assert!(
        (250..=400).contains(&size),
        "promise size {} B drifted far from the ~320 B expected encoding",
        size
    );
    println!("encoded promise = {} B", size);
}
