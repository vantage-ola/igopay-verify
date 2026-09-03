//! Golden cross-platform vectors (`tests/vectors/golden.json`).
//!
//! These pin the EXACT canonical bytes the deterministic `TestSigner` seeds produce
//! for a certificate, two forking promises, and their fork proof, plus the digests
//! and the accepting verdict. Their job is twofold:
//!
//!   1. **Determinism regression guard.** If a refactor changes the wire format or
//!      the signing/encoding path, these byte comparisons fail loudly here rather
//!      than silently breaking interoperability with already-issued artefacts or a
//!      second implementation.
//!   2. **Cross-platform contract.** Any other implementation (or the mobile FFI on
//!      a real device) can load `golden.json` and assert it reaches the same bytes
//!      and the same verdicts — the concrete meaning of "identical bytes ⇒ identical
//!      verdicts".
//!
//! The vectors are regenerated ONLY on a deliberate format change. To regenerate,
//! rebuild the artefacts from the documented seeds and update both the `.json` and
//! the constants any consumer pins.

mod common;

use common::{make_certificate, make_promise, TestSigner};
use igopay_core::crypto::Signer;
use igopay_core::verify::{detect_fork, verify_fork_proof, verify_promise, VerifyContext};
use igopay_core::{
    from_qr_payload, to_qr_payload, BlockList, Certificate, FixedClock, ForkProof, P256Verifier,
    Promise, SlotGrant,
};

// The exact values from tests/vectors/golden.json. Kept as constants so a mismatch
// points straight at the drifting field. If you change the protocol wire format on
// purpose, regenerate golden.json and update these together.
const ISSUER_PK: &str = "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
const PAYER_PK: &str = "037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
const PAYEE_PK: &str = "025ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c";
const PAYEE_B_PK: &str = "02e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852";

const CERT_BODY_DIGEST: &str = "b293f54e3ece2d53b153895a24799c91af3f1756d6114ff299d59fdbc6773dcf";
const PROMISE_BODY_DIGEST: &str =
    "c9605a296a401c05991a2ee3e168bd884d16c09d86f80b234ab62479ee4a5def";

const CERT_HEX: &str = "a9005821037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997801666164756e6e6902020319c35004a3001a6553f100011a6553ff1002183c050a061a6553f100071a6553ff10085840d23996b51d3d8feef8e99ada0e3dab361c36763d34e9eb30fcc10c83b8c4e9e063c42a609e921dcdd16e7f5f8ea5d1e96b759c9241a113c6a0fdd762afae8bb7";
const PROMISE_HEX: &str = "a900a9005821037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997801666164756e6e6902020319c35004a3001a6553f100011a6553ff1002183c050a061a6553f100071a6553ff10085840d23996b51d3d8feef8e99ada0e3dab361c36763d34e9eb30fcc10c83b8c4e9e063c42a609e921dcdd16e7f5f8ea5d1e96b759c9241a113c6a0fdd762afae8bb7015821025ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c0219271003634e474e044c000000000000000000000000050b0658200000000000000000000000000000000000000000000000000000000000000000071a6553f13c085840b06e4187e83af7c9107c0d4f19640c7357dd6563f87eebadadc1eb3d26f44aab53fc68cba63bc4bb947733b2b1bd0bcf66ac603ef43669cfbb7d1571c66176e4";
const FORK_HEX: &str = "82a900a9005821037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997801666164756e6e6902020319c35004a3001a6553f100011a6553ff1002183c050a061a6553f100071a6553ff10085840d23996b51d3d8feef8e99ada0e3dab361c36763d34e9eb30fcc10c83b8c4e9e063c42a609e921dcdd16e7f5f8ea5d1e96b759c9241a113c6a0fdd762afae8bb7015821025ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c0219271003634e474e044c000000000000000000000000050b0658200000000000000000000000000000000000000000000000000000000000000000071a6553f13c085840b06e4187e83af7c9107c0d4f19640c7357dd6563f87eebadadc1eb3d26f44aab53fc68cba63bc4bb947733b2b1bd0bcf66ac603ef43669cfbb7d1571c66176e4a900a9005821037cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997801666164756e6e6902020319c35004a3001a6553f100011a6553ff1002183c050a061a6553f100071a6553ff10085840d23996b51d3d8feef8e99ada0e3dab361c36763d34e9eb30fcc10c83b8c4e9e063c42a609e921dcdd16e7f5f8ea5d1e96b759c9241a113c6a0fdd762afae8bb701582102e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852021961a803634e474e044c000000000000000000000000050b0658200000000000000000000000000000000000000000000000000000000000000000071a6553f13c08584082cdbe309654db23adc6f8ad92650b354d6f99e4b0077e5006287748845f3b1410aa344e56fbc8c91da30a3207c890850269a75448fc6c68f323848e8c560bb2";

// The exact unpadded uppercase base32 QR transport string (D1) for promise_a.
const PROMISE_QR: &str = "VEAKSACYEEBXZ4T3DCGQGT36RJJDQAYEWUNMHQEJNHRHP4Q3GWTAWSH4I5TJS6ABMZQWI5LONZUQEAQDDHBVABFDAANGKU7RAAARUZKT74IAEGB4AUFAMGTFKPYQABY2MVJ76EAILBANEOMWWUOT3D7O7DUZVWQOHWVTMHBWOY6TJ2PLGD6MCDEDXDCOTYDDYQVGBHUSDXG5C3T7L6HKLUPJNN2ZZESBUEJ4NIH525RK7LULW4AVQIICL3F6JUNGGMFEJSHX56KR2S7RMXTMNNZB56W2TBP3IFTBXRXH7VWAEGJHCABWGTSHJYCEYAAAAAAAAAAAAAAAAAAAAUFQMWBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOGTFKPYTYCCYICYG4QMH5A5PPSIQPQGU6GLEBRZVPXLFMP4H525NVXA6WPJG6RFKWU74NDF2MO6EXOKHOM5SWG6QXT3GVRQD55BWNHH3W7IVOHDGC5XE";

const SLOT_FROM: u64 = 1_700_000_000;
const SLOT_TO: u64 = 1_700_003_600;
const SLOT: u64 = 1_700_000_060;
const NOW: u64 = 1_700_000_060;

/// Rebuild certificate + both promises from the documented seeds and grant.
fn build() -> (TestSigner, Certificate, Promise, Promise) {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let payee_b = TestSigner::from_seed(4);
    let grant = SlotGrant {
        from: SLOT_FROM,
        to: SLOT_TO,
        granularity_secs: 60,
    };
    let cert = make_certificate(
        &issuer, &payer, "adunni", 2, 50_000, grant, 10, SLOT_FROM, SLOT_TO,
    );
    let a = make_promise(
        &payer,
        &cert,
        payee.public_key(),
        10_000,
        "NGN",
        &[0u8; 12],
        11,
        [0u8; 32],
        SLOT,
    );
    let b = make_promise(
        &payer,
        &cert,
        payee_b.public_key(),
        25_000,
        "NGN",
        &[0u8; 12],
        11,
        [0u8; 32],
        SLOT,
    );
    (issuer, cert, a, b)
}

#[test]
fn pubkeys_match_golden() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2);
    let payee = TestSigner::from_seed(3);
    let payee_b = TestSigner::from_seed(4);
    assert_eq!(hex::encode(issuer.public_key()), ISSUER_PK);
    assert_eq!(hex::encode(payer.public_key()), PAYER_PK);
    assert_eq!(hex::encode(payee.public_key()), PAYEE_PK);
    assert_eq!(hex::encode(payee_b.public_key()), PAYEE_B_PK);
}

#[test]
fn encoded_bytes_match_golden() {
    let (_issuer, cert, a, b) = build();
    assert_eq!(
        hex::encode(cert.encode()),
        CERT_HEX,
        "certificate bytes drifted"
    );
    assert_eq!(
        hex::encode(a.encode()),
        PROMISE_HEX,
        "promise_a bytes drifted"
    );
    let fork = detect_fork(&a, &b).expect("golden pair is a fork");
    assert_eq!(
        hex::encode(fork.encode()),
        FORK_HEX,
        "fork proof bytes drifted"
    );
}

#[test]
fn qr_transport_payload_matches_golden() {
    // The QR transport string (D1: unpadded uppercase base32, alphanumeric mode) is
    // part of the wire contract — the exact characters a payee scans. Pin it, and
    // prove it round-trips back to the promise bytes.
    let (_issuer, _cert, a, _b) = build();
    let payload = to_qr_payload(&a.encode());
    assert_eq!(payload, PROMISE_QR, "QR base32 payload drifted");

    let decoded = from_qr_payload(PROMISE_QR).expect("golden QR payload decodes");
    assert_eq!(
        decoded,
        a.encode(),
        "QR payload must decode to the promise bytes"
    );
    // And the decoded bytes must parse back to the same promise.
    assert_eq!(Promise::from_bytes(&decoded).unwrap(), a);
}

#[test]
fn digests_match_golden() {
    let (_issuer, cert, a, _b) = build();
    assert_eq!(hex::encode(cert.body_digest()), CERT_BODY_DIGEST);
    assert_eq!(hex::encode(a.body_digest()), PROMISE_BODY_DIGEST);
}

#[test]
fn golden_bytes_decode_back_to_equal_values() {
    // Round-trip the other direction: the pinned bytes must decode to structures
    // that re-encode to the same bytes (canonical) and equal the freshly built ones.
    let (_issuer, cert, a, b) = build();
    let cert_bytes = hex::decode(CERT_HEX).unwrap();
    let promise_bytes = hex::decode(PROMISE_HEX).unwrap();
    let fork_bytes = hex::decode(FORK_HEX).unwrap();

    let decoded_cert = Certificate::from_bytes(&cert_bytes).expect("decode cert");
    assert_eq!(decoded_cert, cert);
    assert_eq!(decoded_cert.encode(), cert_bytes);

    let decoded_promise = Promise::from_bytes(&promise_bytes).expect("decode promise");
    assert_eq!(decoded_promise, a);
    assert_eq!(decoded_promise.encode(), promise_bytes);

    let decoded_fork = ForkProof::from_bytes(&fork_bytes).expect("decode fork");
    assert_eq!(decoded_fork.a, a);
    assert_eq!(decoded_fork.b, b);
    assert_eq!(decoded_fork.encode(), fork_bytes);
}

#[test]
fn golden_promise_reaches_accepted_verdict() {
    // The pinned context must ACCEPT the pinned promise with the pinned exposure.
    let (issuer, _cert, a, _b) = build();
    let payee = TestSigner::from_seed(3);
    let v = P256Verifier;
    let clock = FixedClock(NOW);
    let bl = BlockList::new(4096, 4);
    let issuer_pk = issuer.public_key();
    let payee_pk = payee.public_key();
    let nonce = [0u8; 12];
    let ctx = VerifyContext {
        issuer_pubkey: &issuer_pk,
        my_pubkey: &payee_pk,
        expected_nonce: &nonce,
        block_list: &bl,
        verifier: &v,
        clock: &clock,
        known_head: None,
    };
    let accepted = verify_promise(&a, &ctx).expect("golden promise must accept");
    assert_eq!(accepted.exposure.promises_since_issue, 1);
    assert_eq!(
        hex::encode(accepted.new_head.body_digest),
        PROMISE_BODY_DIGEST
    );
}

#[test]
fn golden_fork_proof_verifies() {
    let fork_bytes = hex::decode(FORK_HEX).unwrap();
    let proof = ForkProof::from_bytes(&fork_bytes).expect("decode fork");
    assert!(
        verify_fork_proof(&proof, &P256Verifier),
        "golden fork must verify"
    );
}
