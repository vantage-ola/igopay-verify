//! Block-list publication from the registry (B13).
//!
//! The wire-format and install rules are proved in `igopay-core/tests/blocklist.rs`.
//! These tests cover the issuer's side of the seam: that everything the registry has
//! blocked reaches the published artefact, that nothing else does, and that the policy
//! knobs produce a list a device will actually accept.

mod common;

use common::{issue_cert, promise, TestSigner, GRANT_FROM};
use igopay_core::crypto::Signer;
use igopay_core::{InstalledBlockList, P256Verifier, SignedBlockList, MAX_EXACT_RECENT};
use igopay_issuer::{publish_block_list, PromiseRegistry, PublishParams, Submission};

/// Drive a payer into the blocked set by double spending `seq = 1`.
fn block_payer(reg: &mut PromiseRegistry, issuer: &TestSigner, payer: &TestSigner) {
    let cert = issue_cert(issuer, payer, 0);
    let payee = TestSigner::from_seed(200).public_key();
    let a = promise(payer, &cert, payee, 1_000, b"n1", 1, [0u8; 32], GRANT_FROM);
    let b = promise(payer, &cert, payee, 9_000, b"n2", 1, [0u8; 32], GRANT_FROM);
    assert!(matches!(
        reg.submit(&a, &P256Verifier).unwrap(),
        Submission::Accepted { .. }
    ));
    assert!(matches!(
        reg.submit(&b, &P256Verifier).unwrap(),
        Submission::Fork(_)
    ));
}

/// Publish and install in one step, as an issuer and then a device would.
fn publish_and_install(
    reg: &PromiseRegistry,
    issuer: &TestSigner,
    params: &PublishParams,
    current_epoch: Option<u64>,
) -> InstalledBlockList {
    let doc = publish_block_list(reg, params, issuer);
    doc.verify_and_open(&issuer.public_key(), &P256Verifier, current_epoch)
        .expect("a list the issuer just signed must install")
}

#[test]
fn every_blocked_payer_appears_in_the_published_list() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());

    let payers: Vec<TestSigner> = (10..15).map(TestSigner::from_seed).collect();
    for p in &payers {
        block_payer(&mut reg, &issuer, p);
    }
    assert_eq!(reg.blocked_count(), 5);

    let installed = publish_and_install(&reg, &issuer, &PublishParams::new(1, 1_000), None);
    for p in &payers {
        assert!(
            installed.contains(&p.public_key()),
            "a blocked payer was missing from the published list"
        );
    }
}

#[test]
fn a_payer_who_never_forked_is_not_in_the_list() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut reg, &issuer, &TestSigner::from_seed(10));

    // Clean payers, including one who submitted a promise and behaved.
    let honest = TestSigner::from_seed(20);
    let cert = issue_cert(&issuer, &honest, 0);
    let payee = TestSigner::from_seed(200).public_key();
    let p = promise(
        &honest, &cert, payee, 1_000, b"ok", 1, [0u8; 32], GRANT_FROM,
    );
    reg.submit(&p, &P256Verifier).unwrap();

    let installed = publish_and_install(&reg, &issuer, &PublishParams::new(1, 1_000), None);
    assert!(!installed.contains(&honest.public_key()));
    for seed in 30..60u8 {
        let stranger = TestSigner::from_seed(seed).public_key();
        assert!(
            !installed.contains(&stranger),
            "false positive at seed {seed}"
        );
    }
}

#[test]
fn the_most_recently_blocked_payers_get_the_exact_treatment() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());

    let payers: Vec<TestSigner> = (10..15).map(TestSigner::from_seed).collect();
    for p in &payers {
        block_payer(&mut reg, &issuer, p);
    }

    let mut params = PublishParams::new(1, 1_000);
    params.exact_recent = 2;
    let installed = publish_and_install(&reg, &issuer, &params, None);

    // The last two blocked are certain; all five are still blocked.
    for p in &payers[3..] {
        assert!(installed.contains_exact(&p.public_key()));
    }
    for p in &payers[..3] {
        assert!(!installed.contains_exact(&p.public_key()));
        assert!(installed.contains(&p.public_key()));
    }
}

#[test]
fn exact_entries_are_in_the_filter_as_well() {
    // The invariant that lets a consumer ignore the exact set and still be correct, and
    // that stops a payer becoming unblocked when they age out of the exact window.
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    let payers: Vec<TestSigner> = (10..14).map(TestSigner::from_seed).collect();
    for p in &payers {
        block_payer(&mut reg, &issuer, p);
    }

    let installed = publish_and_install(&reg, &issuer, &PublishParams::new(1, 1_000), None);
    for p in &payers {
        assert!(installed.contains_exact(&p.public_key()));
        assert!(
            installed.contains_in_filter(&p.public_key()),
            "an exact-set payer was left out of the filter"
        );
    }
}

#[test]
fn an_empty_registry_publishes_a_list_that_blocks_nobody() {
    let issuer = TestSigner::from_seed(1);
    let reg = PromiseRegistry::new(issuer.public_key());

    let doc = publish_block_list(&reg, &PublishParams::new(1, 1_000), &issuer);
    assert!(doc.exact_recent.is_empty());

    let installed = doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .expect("an empty list is still a valid list");
    for seed in 2..80u8 {
        assert!(!installed.contains(&TestSigner::from_seed(seed).public_key()));
    }
}

#[test]
fn a_published_list_survives_the_wire() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    let payer = TestSigner::from_seed(10);
    block_payer(&mut reg, &issuer, &payer);

    let doc = publish_block_list(&reg, &PublishParams::new(4, 1_000), &issuer);
    let bytes = doc.encode();
    let decoded = SignedBlockList::decode(&bytes).expect("decodes on the device");
    assert_eq!(decoded, doc);

    let installed = decoded
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .expect("installs");
    assert!(installed.contains(&payer.public_key()));
    assert_eq!(installed.epoch(), 4);
    assert_eq!(installed.not_after(), 1_000 + 24 * 60 * 60);
}

#[test]
fn successive_publications_install_in_order_and_never_backwards() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    let first = TestSigner::from_seed(10);
    block_payer(&mut reg, &issuer, &first);

    let e1 = publish_block_list(&reg, &PublishParams::new(1, 1_000), &issuer);
    let held = e1
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .unwrap();
    assert_eq!(held.epoch(), 1);

    // A second payer is caught, a second list goes out.
    let second = TestSigner::from_seed(11);
    block_payer(&mut reg, &issuer, &second);
    let e2 = publish_block_list(&reg, &PublishParams::new(2, 2_000), &issuer);
    let held2 = e2
        .verify_and_open(&issuer.public_key(), &P256Verifier, Some(held.epoch()))
        .unwrap();
    assert!(held2.contains(&first.public_key()));
    assert!(held2.contains(&second.public_key()));

    // Replaying epoch 1 must not un-block the second payer.
    assert!(e1
        .verify_and_open(&issuer.public_key(), &P256Verifier, Some(held2.epoch()))
        .is_err());
}

#[test]
fn a_payer_blocked_by_a_submitted_fork_proof_is_published_too() {
    // The other way into the blocked set: a payee's own ledger caught the fork and sent
    // the proof up, rather than the issuer noticing a collision.
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    let payer = TestSigner::from_seed(12);
    let cert = issue_cert(&issuer, &payer, 0);
    let payee = TestSigner::from_seed(200).public_key();
    let a = promise(&payer, &cert, payee, 1_000, b"n1", 3, [0u8; 32], GRANT_FROM);
    let b = promise(&payer, &cert, payee, 7_000, b"n2", 3, [0u8; 32], GRANT_FROM);
    let proof = igopay_core::detect_fork(&a, &b).expect("is a fork");

    assert!(reg.submit_fork_proof(&proof, &P256Verifier).unwrap());

    let installed = publish_and_install(&reg, &issuer, &PublishParams::new(1, 1_000), None);
    assert!(installed.contains(&payer.public_key()));
    assert!(installed.contains_exact(&payer.public_key()));
}

#[test]
fn re_blocking_does_not_move_a_payer_in_the_recency_order() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    let a = TestSigner::from_seed(10);
    let b = TestSigner::from_seed(11);
    block_payer(&mut reg, &issuer, &a);
    block_payer(&mut reg, &issuer, &b);
    assert_eq!(
        reg.blocked_in_block_order(),
        vec![a.public_key(), b.public_key()]
    );

    // A second, different fork from the same payer. They are already blocked, so their
    // position must not jump to the front of the exact-set window.
    let cert = issue_cert(&issuer, &a, 0);
    let payee = TestSigner::from_seed(201).public_key();
    let p1 = promise(&a, &cert, payee, 500, b"x1", 9, [0u8; 32], GRANT_FROM);
    let p2 = promise(&a, &cert, payee, 600, b"x2", 9, [0u8; 32], GRANT_FROM);
    reg.submit(&p1, &P256Verifier).unwrap();
    assert!(matches!(
        reg.submit(&p2, &P256Verifier).unwrap(),
        Submission::Fork(_)
    ));

    assert_eq!(reg.blocked_count(), 2);
    assert_eq!(
        reg.blocked_in_block_order(),
        vec![a.public_key(), b.public_key()]
    );
}

#[test]
fn the_filter_floor_applies_to_small_lists() {
    // One blocked payer at 12 bits/item would be a 12-bit filter, where 8 probes leave
    // almost every bit set and the nominal error rate is meaningless.
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut reg, &issuer, &TestSigner::from_seed(10));

    let doc = publish_block_list(&reg, &PublishParams::new(1, 1_000), &issuer);
    assert_eq!(doc.num_bits, 512);
    assert_eq!(doc.bits.len(), 64);
}

#[test]
fn an_oversized_exact_request_is_clamped_to_what_a_device_accepts() {
    let issuer = TestSigner::from_seed(1);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut reg, &issuer, &TestSigner::from_seed(10));

    let mut params = PublishParams::new(1, 1_000);
    params.exact_recent = MAX_EXACT_RECENT + 10_000;
    let doc = publish_block_list(&reg, &params, &issuer);

    assert!(doc.exact_recent.len() <= MAX_EXACT_RECENT);
    assert!(SignedBlockList::decode(&doc.encode()).is_ok());
}

#[test]
fn a_list_from_a_different_issuer_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(2);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut reg, &issuer, &TestSigner::from_seed(10));

    // Signed by a key the device does not trust.
    let doc = publish_block_list(&reg, &PublishParams::new(1, 1_000), &rival);
    assert!(doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .is_err());
}
