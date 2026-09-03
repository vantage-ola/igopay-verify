//! The issuer's checkpoint log (B7).
//!
//! `igopay-core/tests/checkpoint.rs` proves what a *device* does with a checkpoint. These
//! prove the publisher's side, and the sharpest test in the file is
//! `two_publisher_processes_that_bypass_the_log_are_caught`: it builds the exact failure
//! B7 exists for — the issuer shipping two different block lists at one epoch — and shows
//! that the log refuses it when it is a mistake, and convicts when it is not.

mod common;

use common::{issue_cert, promise, TestSigner, GRANT_FROM};
use igopay_core::checkpoint::install_checkpointed_list;
use igopay_core::crypto::Signer;
use igopay_core::{
    detect_equivocation, verify_equivocation_proof, CheckpointError, CheckpointTracker,
    CheckpointVerdict, EquivocationKind, P256Verifier, SignedBlockList,
};
use igopay_issuer::{
    publish_block_list, publish_with_checkpoint, CheckpointLog, LogError, PromiseRegistry,
    PublishParams, Submission,
};

/// Drive a payer into the blocked set by double spending `seq = 1`.
fn block_payer(reg: &mut PromiseRegistry, issuer: &TestSigner, payer: &TestSigner) {
    let cert = issue_cert(issuer, payer, 0);
    let payee = TestSigner::from_seed(200).public_key();
    let a = promise(payer, &cert, payee, 1_000, b"n1", 1, [0u8; 32], GRANT_FROM);
    let b = promise(payer, &cert, payee, 9_000, b"n2", 1, [0u8; 32], GRANT_FROM);
    reg.submit(&a, &P256Verifier).unwrap();
    assert!(matches!(
        reg.submit(&b, &P256Verifier).unwrap(),
        Submission::Fork(_)
    ));
}

/// A registry with `n` blocked payers, seeded deterministically.
fn registry_with_blocked(issuer: &TestSigner, n: u8) -> PromiseRegistry {
    let mut reg = PromiseRegistry::new(issuer.public_key());
    for seed in 10..(10 + n) {
        block_payer(&mut reg, issuer, &TestSigner::from_seed(seed));
    }
    reg
}

fn params(epoch: u64) -> PublishParams {
    PublishParams::new(epoch, 1_000_000 + epoch)
}

// ---------------------------------------------------------------------------
// Appending
// ---------------------------------------------------------------------------

#[test]
fn the_first_publication_starts_the_chain() {
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 2);
    let mut log = CheckpointLog::new(issuer.public_key());

    let pubn = publish_with_checkpoint(&reg, &params(1), &issuer, &mut log).expect("publishes");
    assert!(pubn.checkpoint.is_genesis());
    assert_eq!(pubn.checkpoint.seq, 0);
    assert_eq!(pubn.checkpoint.epoch, 1);
    assert_eq!(pubn.checkpoint.list_digest, pubn.list.body_digest());
    assert_eq!(log.len(), 1);
    assert_eq!(log.next_seq(), 1);
    log.audit(&P256Verifier).expect("honest log audits");
}

#[test]
fn successive_publications_link_and_advance() {
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 2);
    let mut log = CheckpointLog::new(issuer.public_key());

    for epoch in 1..=5 {
        let pubn =
            publish_with_checkpoint(&reg, &params(epoch), &issuer, &mut log).expect("publishes");
        assert_eq!(pubn.checkpoint.seq, epoch - 1);
        assert_eq!(pubn.checkpoint.epoch, epoch);
    }
    // Position and epoch are different counters, and the log proves it: five entries at
    // positions 0..=4 carrying epochs 1..=5.
    assert_eq!(log.len(), 5);
    assert_eq!(log.head().unwrap().seq, 4);
    assert_eq!(log.head().unwrap().epoch, 5);
    log.audit(&P256Verifier).expect("honest log audits");
}

#[test]
fn a_reused_epoch_is_refused_before_anything_is_distributed() {
    // The guard rail. Two racing publisher processes, or one operator running the job
    // twice, cannot produce two epoch-3 lists: the second attempt is refused here, not
    // discovered later on somebody's phone.
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());

    publish_with_checkpoint(&reg, &params(3), &issuer, &mut log).expect("publishes");
    assert_eq!(
        publish_with_checkpoint(&reg, &params(3), &issuer, &mut log).unwrap_err(),
        LogError::EpochNotAdvancing {
            head: 3,
            offered: 3
        }
    );
    assert_eq!(
        log.len(),
        1,
        "a refused publication must not extend the log"
    );
}

#[test]
fn an_older_epoch_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());

    publish_with_checkpoint(&reg, &params(9), &issuer, &mut log).expect("publishes");
    assert_eq!(
        publish_with_checkpoint(&reg, &params(4), &issuer, &mut log).unwrap_err(),
        LogError::EpochNotAdvancing {
            head: 9,
            offered: 4
        }
    );
}

#[test]
fn an_epoch_gap_is_fine_and_the_positions_stay_contiguous() {
    // Why the two counters are separate. A service that increments its epoch counter and
    // then fails mid-publish leaves a legitimate gap in the epochs; treating that as fraud
    // would convict an honest issuer for crashing. Positions cannot gap, because the log
    // assigns them.
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());

    publish_with_checkpoint(&reg, &params(1), &issuer, &mut log).expect("publishes");
    publish_with_checkpoint(&reg, &params(50), &issuer, &mut log).expect("publishes");
    publish_with_checkpoint(&reg, &params(51), &issuer, &mut log).expect("publishes");

    let seqs: Vec<u64> = log.entries().iter().map(|c| c.seq).collect();
    let epochs: Vec<u64> = log.entries().iter().map(|c| c.epoch).collect();
    assert_eq!(seqs, vec![0, 1, 2]);
    assert_eq!(epochs, vec![1, 50, 51]);
    log.audit(&P256Verifier).expect("gaps in epoch are honest");
}

#[test]
fn the_wrong_signing_key_is_refused() {
    // Appending with the wrong key would produce a chain every device rejects — an outage
    // that would surface hours later on a phone. Caught at the append.
    let issuer = TestSigner::from_seed(1);
    let other = TestSigner::from_seed(2);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());

    assert_eq!(
        publish_with_checkpoint(&reg, &params(1), &other, &mut log).unwrap_err(),
        LogError::WrongSigner
    );
    assert!(log.is_empty());

    let list = publish_block_list(&reg, &params(1), &other);
    assert_eq!(
        log.append_for_list(&list, 1_000_000, &other).unwrap_err(),
        LogError::WrongSigner
    );
}

// ---------------------------------------------------------------------------
// The device end of the same seam
// ---------------------------------------------------------------------------

#[test]
fn a_checkpointed_publication_installs_on_a_device() {
    let issuer = TestSigner::from_seed(1);
    let cheat = TestSigner::from_seed(10);
    let mut reg = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut reg, &issuer, &cheat);

    let mut log = CheckpointLog::new(issuer.public_key());
    let pubn = publish_with_checkpoint(&reg, &params(1), &issuer, &mut log).expect("publishes");

    let mut tracker = CheckpointTracker::new(issuer.public_key(), 16);
    assert_eq!(
        tracker.offer(&pubn.checkpoint, &P256Verifier).unwrap(),
        CheckpointVerdict::FirstSeen
    );
    let installed = install_checkpointed_list(
        &pubn.list,
        &pubn.checkpoint,
        &issuer.public_key(),
        &P256Verifier,
        None,
    )
    .expect("installs");
    assert!(installed.contains(&cheat.public_key()));
    assert!(tracker.commits_to(&pubn.list));
}

#[test]
fn a_lagging_device_catches_up_from_the_log() {
    // `since` is what an issuer hands a device that has been offline: the missing entries,
    // in order, each of which the device then accepts as a plain `Advanced`.
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=6 {
        publish_with_checkpoint(&reg, &params(epoch), &issuer, &mut log).expect("publishes");
    }

    let mut tracker = CheckpointTracker::new(issuer.public_key(), 16);
    tracker.offer(log.at(1).unwrap(), &P256Verifier).unwrap();

    let missing = log.since(1);
    assert_eq!(missing.len(), 4);
    for cp in missing {
        assert_eq!(
            tracker.offer(cp, &P256Verifier).unwrap(),
            CheckpointVerdict::Advanced
        );
    }
    assert_eq!(tracker.head().unwrap().seq, 5);
    assert_eq!(log.since(5).len(), 0);
    assert_eq!(log.since(99).len(), 0);
}

// ---------------------------------------------------------------------------
// The attack the whole feature is for
// ---------------------------------------------------------------------------

#[test]
fn two_publisher_processes_that_bypass_the_log_are_caught() {
    // The hole, played out. Suppose the issuer really does want two stories at epoch 7 —
    // one list that blocks a payer, one that does not — and runs two publishers to get
    // them, each keeping its own log. Nothing can stop it *signing* both. What it cannot do
    // is stop the two devices comparing notes afterwards.
    let issuer = TestSigner::from_seed(1);
    let cheat = TestSigner::from_seed(10);

    let mut with_cheat = PromiseRegistry::new(issuer.public_key());
    block_payer(&mut with_cheat, &issuer, &cheat);
    let without_cheat = PromiseRegistry::new(issuer.public_key());

    let mut log_a = CheckpointLog::new(issuer.public_key());
    let mut log_b = CheckpointLog::new(issuer.public_key());
    let story_a =
        publish_with_checkpoint(&with_cheat, &params(7), &issuer, &mut log_a).expect("publishes");
    let story_b = publish_with_checkpoint(&without_cheat, &params(7), &issuer, &mut log_b)
        .expect("publishes");

    // Both lists are perfectly signed, and each installs on its own device. This is exactly
    // why the signature alone was never enough.
    assert_ne!(story_a.list.body_digest(), story_b.list.body_digest());
    for story in [&story_a, &story_b] {
        install_checkpointed_list(
            &story.list,
            &story.checkpoint,
            &issuer.public_key(),
            &P256Verifier,
            None,
        )
        .expect("each story installs on its own device");
    }

    // Device A is told story A. It later meets device B — at a market, through a carried
    // bundle — and is offered story B's checkpoint.
    let mut device_a = CheckpointTracker::new(issuer.public_key(), 16);
    device_a.offer(&story_a.checkpoint, &P256Verifier).unwrap();
    let verdict = device_a.offer(&story_b.checkpoint, &P256Verifier).unwrap();

    let proof = match verdict {
        CheckpointVerdict::Equivocation(p) => p,
        other => panic!("expected equivocation, got {other:?}"),
    };
    assert_eq!(
        verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).unwrap(),
        EquivocationKind::DuplicatePosition
    );
    // And the evidence is portable: it survives the wire, and nothing about verifying it
    // requires trusting the device that found it.
    let bytes = proof.encode();
    let reread = igopay_core::EquivocationProof::from_bytes(&bytes).expect("decodes");
    verify_equivocation_proof(&reread, &issuer.public_key(), &P256Verifier).expect("verifies");

    // Device A keeps the story it was given. It is now holding proof, not confusion.
    assert_eq!(device_a.head().unwrap(), &story_a.checkpoint);
}

#[test]
fn the_dispute_desk_can_answer_from_the_log() {
    // A payee turns up with "this is what I was told". The log answers whether it agrees,
    // and the answer is two of the issuer's own signatures rather than the issuer's word.
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut real = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=3 {
        publish_with_checkpoint(&reg, &params(epoch), &issuer, &mut real).expect("publishes");
    }

    // A second story at position 0, built off-log: an epoch-1 list that blocks nobody.
    let clean = PromiseRegistry::new(issuer.public_key());
    let mut shadow = CheckpointLog::new(issuer.public_key());
    let foreign =
        publish_with_checkpoint(&clean, &params(1), &issuer, &mut shadow).expect("publishes");

    let proof = real
        .conflicting(&foreign.checkpoint)
        .expect("the log disagrees");
    assert_eq!(
        verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).unwrap(),
        EquivocationKind::DuplicatePosition
    );

    // A checkpoint that IS from this log is not a conflict.
    for cp in real.entries() {
        assert!(real.conflicting(cp).is_none());
    }
}

// ---------------------------------------------------------------------------
// Resume and audit
// ---------------------------------------------------------------------------

#[test]
fn resuming_verifies_the_whole_chain() {
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 1);
    let mut log = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=4 {
        publish_with_checkpoint(&reg, &params(epoch), &issuer, &mut log).expect("publishes");
    }

    let persisted = log.entries().to_vec();
    let resumed = CheckpointLog::resume(issuer.public_key(), persisted.clone(), &P256Verifier)
        .expect("honest history resumes");
    assert_eq!(resumed.len(), 4);
    assert_eq!(resumed.head(), log.head());

    // A restart is the easiest moment to slip in a rewrite, so resume re-checks everything.
    let mut tampered = persisted.clone();
    tampered[2].list_digest[0] ^= 0xff;
    assert!(matches!(
        CheckpointLog::resume(issuer.public_key(), tampered, &P256Verifier).unwrap_err(),
        LogError::Corrupt(CheckpointError::BadIssuerSignature)
    ));

    // A dropped entry is refused too: positions must be contiguous from 0.
    let mut with_hole = persisted.clone();
    with_hole.remove(1);
    assert_eq!(
        CheckpointLog::resume(issuer.public_key(), with_hole, &P256Verifier).unwrap_err(),
        LogError::NotContiguous {
            expected: 1,
            got: 2
        }
    );

    // And a rival's chain does not become ours by being handed to us.
    let rival = TestSigner::from_seed(2);
    assert!(matches!(
        CheckpointLog::resume(rival.public_key(), persisted, &P256Verifier).unwrap_err(),
        LogError::Corrupt(CheckpointError::BadIssuerSignature)
    ));
}

#[test]
fn an_empty_log_is_valid_and_says_nothing() {
    let issuer = TestSigner::from_seed(1);
    let log = CheckpointLog::new(issuer.public_key());
    assert!(log.is_empty());
    assert!(log.head().is_none());
    assert_eq!(log.next_seq(), 0);
    log.audit(&P256Verifier).expect("an empty log audits");
    assert!(log.since(0).is_empty());
    assert!(CheckpointLog::resume(issuer.public_key(), Vec::new(), &P256Verifier).is_ok());
}

#[test]
fn a_checkpoint_commits_to_the_exact_bytes_that_were_published() {
    // If the digest were taken over anything but the list body, an issuer could swap the
    // list's signature or its wrapper and claim the same checkpoint covered it.
    let issuer = TestSigner::from_seed(1);
    let reg = registry_with_blocked(&issuer, 3);
    let mut log = CheckpointLog::new(issuer.public_key());
    let pubn = publish_with_checkpoint(&reg, &params(1), &issuer, &mut log).expect("publishes");

    let wire = pubn.list.encode();
    let decoded = SignedBlockList::decode(&wire).expect("decodes");
    assert_eq!(decoded.body_digest(), pubn.checkpoint.list_digest);

    // A re-signed but otherwise identical list is the same list, so the commitment still
    // holds — identity is the body, not the signature.
    let mut resigned = decoded.clone();
    resigned.sig_issuer = issuer.sign_prehash(&resigned.body_digest());
    assert_eq!(resigned.body_digest(), pubn.checkpoint.list_digest);

    // One extra blocked payer, and it does not.
    let mut reg2 = registry_with_blocked(&issuer, 3);
    block_payer(&mut reg2, &issuer, &TestSigner::from_seed(99));
    let other = publish_block_list(&reg2, &params(1), &issuer);
    assert_ne!(other.body_digest(), pubn.checkpoint.list_digest);

    let mut rival_log = CheckpointLog::new(issuer.public_key());
    let rival_cp = rival_log
        .append_for_list(&other, 1_000_001, &issuer)
        .expect("appends")
        .clone();
    assert!(detect_equivocation(&pubn.checkpoint, &rival_cp).is_some());
}
