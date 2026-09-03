//! The external anchor seam (B7's other half).
//!
//! Mostly negative, and deliberately so. The failure this seam exists to prevent is not a
//! crash — it is a dashboard reading "anchored" while nothing was ever published anywhere.
//! So what gets asserted hardest is that the inert implementation stays honest about being
//! inert, and that a claim of public visibility must point at something.

mod common;

use common::TestSigner;
use igopay_core::checkpoint::Checkpoint;
use igopay_core::crypto::Signer;
use igopay_core::witness::{verify_witnessed, Cosignature, WitnessLog, WitnessedCheckpoint};
use igopay_core::{verify_equivocation_proof, Hash, P256Verifier, WitnessRefusal};
use igopay_issuer::anchor::{audit_anchored_head, AnchorAudit, AnchorSink, AnchorStatus};
use igopay_issuer::{
    publish_with_checkpoint, CheckpointLog, ManualAnchor, NoOpAnchor, PromiseRegistry,
    PublishParams, WitnessAnchor,
};

fn params(epoch: u64) -> PublishParams {
    PublishParams::new(epoch, 1_000_000 + epoch)
}

/// A log with `n` publications and the issuer that signed it.
fn log_with(issuer: &TestSigner, n: u64) -> CheckpointLog {
    let reg = PromiseRegistry::new(issuer.public_key());
    let mut log = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=n {
        publish_with_checkpoint(&reg, &params(epoch), issuer, &mut log).expect("publishes");
    }
    log
}

// ---------------------------------------------------------------------------
// NoOpAnchor: inert, and says so
// ---------------------------------------------------------------------------

#[test]
fn the_noop_anchor_can_never_report_anchored() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 3);
    let mut sink = NoOpAnchor::new();

    for cp in log.entries() {
        let status = sink.submit(cp);
        assert_eq!(status, AnchorStatus::Unanchored);
        assert!(!status.is_publicly_visible());
    }
    assert_eq!(sink.len(), 3);
}

#[test]
fn the_noop_anchor_still_distinguishes_unanchored_from_never_submitted() {
    // The difference between a sink that is inert and a publication path that silently
    // skipped it. Both are "not anchored"; only one is a bug.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 2);
    let mut sink = NoOpAnchor::new();
    let head = log.head().unwrap();
    sink.submit(head);

    assert_eq!(
        sink.status(&head.body_digest()),
        Some(AnchorStatus::Unanchored)
    );
    assert_eq!(sink.status(&log.at(0).unwrap().body_digest()), None);
    assert_eq!(sink.status(&[7u8; 32]), None);
}

// ---------------------------------------------------------------------------
// ManualAnchor: a human, and a reference
// ---------------------------------------------------------------------------

#[test]
fn a_manually_published_head_becomes_visible_only_with_a_reference() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 2);
    let head = log.head().unwrap();
    let digest = head.body_digest();
    let mut sink = ManualAnchor::new();

    let status = sink.submit(head);
    assert_eq!(
        status,
        AnchorStatus::Pending {
            submitted_at: head.issued_at
        }
    );
    assert!(
        !status.is_publicly_visible(),
        "pending is not a success state: an unconfirmed timestamp is not readable by anyone"
    );
    assert_eq!(sink.pending_queue().len(), 1);
    assert_eq!(sink.pending_queue()[0].seq, head.seq);

    assert!(sink.confirm(&digest, "ots:abc123".into(), 1_002_000));
    assert_eq!(
        sink.status(&digest),
        Some(AnchorStatus::Anchored {
            reference: "ots:abc123".into(),
            confirmed_at: 1_002_000
        })
    );
    assert!(sink.status(&digest).unwrap().is_publicly_visible());
    assert!(sink.pending_queue().is_empty());
    assert_eq!(sink.latest_anchored().map(|(d, _)| *d), Some(digest));
}

#[test]
fn a_confirmation_with_nothing_to_point_at_is_refused() {
    // The whole point of the reference is that a stranger can check without asking us. An
    // empty one is the false assurance this module exists to refuse.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();
    let digest = head.body_digest();
    let mut sink = ManualAnchor::new();
    sink.submit(head);

    assert!(!sink.confirm(&digest, String::new(), 1_002_000));
    assert!(!sink.confirm(&digest, "   ".into(), 1_002_000));
    assert!(matches!(
        sink.status(&digest),
        Some(AnchorStatus::Pending { .. })
    ));
    assert!(sink.latest_anchored().is_none());
}

#[test]
fn confirming_something_never_submitted_is_refused() {
    let mut sink = ManualAnchor::new();
    assert!(!sink.confirm(&[3u8; 32], "ots:xyz".into(), 1_000));
    assert!(sink.status(&[3u8; 32]).is_none());
}

#[test]
fn resubmitting_a_head_neither_double_queues_nor_undoes_a_confirmation() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();
    let digest = head.body_digest();
    let mut sink = ManualAnchor::new();

    sink.submit(head);
    sink.submit(head);
    assert_eq!(sink.pending_queue().len(), 1);

    sink.confirm(&digest, "ots:abc".into(), 1_002_000);
    let after = sink.submit(head);
    assert!(
        after.is_publicly_visible(),
        "a resubmission must not roll a confirmed head back to pending"
    );
}

#[test]
fn both_sinks_are_interchangeable_through_the_trait() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();

    let sinks: Vec<Box<dyn AnchorSink>> =
        vec![Box::new(NoOpAnchor::new()), Box::new(ManualAnchor::new())];
    for mut sink in sinks {
        let name = sink.name();
        let status = sink.submit(head);
        assert!(
            !status.is_publicly_visible(),
            "{name} claimed public visibility on submission"
        );
        assert!(sink.status(&head.body_digest()).is_some());
    }
}

// ---------------------------------------------------------------------------
// The audit anyone can run
// ---------------------------------------------------------------------------

#[test]
fn an_anchored_head_reconciles_against_the_log() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 3);
    let head_digest = log.head().unwrap().body_digest();
    assert_eq!(
        audit_anchored_head(&log, Some(&head_digest)),
        AnchorAudit::HeadMatches { seq: 2 }
    );
}

#[test]
fn an_anchor_that_lags_publication_is_normal() {
    // Anchoring is slower than publishing, so "behind" is the steady state, not a fault.
    // What it costs is precise: everything up to that position is publicly pinned, and
    // everything after it rests on the issuer's word until the next anchor.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 5);
    let older = log.at(1).unwrap().body_digest();
    assert_eq!(
        audit_anchored_head(&log, Some(&older)),
        AnchorAudit::Behind { seq: 1, head: 4 }
    );
}

#[test]
fn a_head_that_is_not_in_the_log_is_the_alarm() {
    // Two issuer log copies, one publication each, different content: the digest anchored
    // from one is nowhere in the other. That is the signal a rewrite or a split view has
    // happened — and, importantly, not by itself the proof.
    let issuer = TestSigner::from_seed(1);
    let real = log_with(&issuer, 3);

    let mut other = CheckpointLog::new(issuer.public_key());
    let mut reg = PromiseRegistry::new(issuer.public_key());
    // A different epoch-1 list: one blocked payer instead of none.
    let cheat = TestSigner::from_seed(10);
    let cert = igopay_core::build_certificate(
        &issuer,
        cheat.public_key(),
        "cheat".into(),
        1,
        10_000,
        common::grant(),
        0,
        0,
        100_000,
    );
    let payee = TestSigner::from_seed(200).public_key();
    let a = common::promise(
        &cheat,
        &cert,
        payee,
        1_000,
        b"n1",
        1,
        [0u8; 32],
        common::GRANT_FROM,
    );
    let b = common::promise(
        &cheat,
        &cert,
        payee,
        2_000,
        b"n2",
        1,
        [0u8; 32],
        common::GRANT_FROM,
    );
    reg.submit(&a, &P256Verifier).unwrap();
    reg.submit(&b, &P256Verifier).unwrap();
    let sneaky = publish_with_checkpoint(&reg, &params(1), &issuer, &mut other).expect("publishes");

    assert_eq!(
        audit_anchored_head(&real, Some(&sneaky.checkpoint.body_digest())),
        AnchorAudit::NotInLog
    );

    // And the promotion from alarm to proof needs the signed checkpoint behind that digest,
    // which is why an anchor stores the digest and somebody keeps the checkpoint.
    assert!(real.conflicting(&sneaky.checkpoint).is_some());
}

#[test]
fn nothing_anchored_claims_nothing() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 2);
    let empty = CheckpointLog::new(issuer.public_key());
    let digest: Hash = [1u8; 32];

    assert_eq!(audit_anchored_head(&log, None), AnchorAudit::Nothing);
    assert_eq!(
        audit_anchored_head(&empty, Some(&digest)),
        AnchorAudit::Nothing
    );
    assert_eq!(audit_anchored_head(&empty, None), AnchorAudit::Nothing);
}

// ---------------------------------------------------------------------------
// WitnessAnchor: the one an offline payee can check
// ---------------------------------------------------------------------------

/// Cosign `cp` as `witness` would, through the core's witness log.
fn cosign(issuer: &TestSigner, witness: &TestSigner, cp: &Checkpoint, at: u64) -> Cosignature {
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    log.cosign(cp, at, witness, &P256Verifier).expect("cosigns")
}

#[test]
fn a_head_is_anchored_only_once_the_threshold_is_met() {
    let issuer = TestSigner::from_seed(1);
    let w1 = TestSigner::from_seed(2);
    let w2 = TestSigner::from_seed(3);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();
    let digest = head.body_digest();

    let mut sink = WitnessAnchor::new(
        issuer.public_key(),
        vec![w1.public_key(), w2.public_key()],
        2,
    );
    assert!(matches!(sink.submit(head), AnchorStatus::Pending { .. }));

    assert!(sink.record_cosignature(cosign(&issuer, &w1, head, 1_500_000), &P256Verifier));
    assert!(
        !sink.status(&digest).unwrap().is_publicly_visible(),
        "one of two witnesses is not the threshold"
    );

    assert!(sink.record_cosignature(cosign(&issuer, &w2, head, 1_500_100), &P256Verifier));
    match sink.status(&digest).unwrap() {
        AnchorStatus::Anchored {
            reference,
            confirmed_at,
        } => {
            assert!(reference.starts_with("witness:"));
            assert_eq!(confirmed_at, 1_500_100, "the latest attestation time");
        }
        other => panic!("expected anchored, got {other:?}"),
    }
    assert_eq!(sink.coverage(&digest), 2);
}

#[test]
fn the_collected_artefact_verifies_on_a_device() {
    // The point of collecting: what ships with the block list is checkable offline.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();

    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![witness.public_key()], 1);
    sink.submit(head);
    sink.record_cosignature(cosign(&issuer, &witness, head, 1_500_000), &P256Verifier);

    let artefact = sink.witnessed(&head.body_digest()).expect("collected");
    let coverage = verify_witnessed(
        artefact,
        &issuer.public_key(),
        &[witness.public_key()],
        &P256Verifier,
    )
    .expect("verifies");
    assert_eq!(coverage.witnesses, 1);
    // And it survives the wire on the way to the phone.
    let back = WitnessedCheckpoint::from_bytes(&artefact.encode()).expect("decodes");
    assert_eq!(&back, artefact);
}

#[test]
fn a_cosignature_from_an_untrusted_or_lying_witness_is_not_recorded() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let stranger = TestSigner::from_seed(4);
    let log = log_with(&issuer, 2);
    let head = log.head().unwrap();
    let digest = head.body_digest();

    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![witness.public_key()], 1);
    sink.submit(head);

    // Not in the trusted set.
    assert!(!sink.record_cosignature(cosign(&issuer, &stranger, head, 1_500_000), &P256Verifier));
    // Trusted, but the signature does not verify. An issuer that kept this would ship an
    // artefact every device rejects.
    let mut tampered = cosign(&issuer, &witness, head, 1_500_000);
    tampered.sig_witness[3] ^= 0xff;
    assert!(!sink.record_cosignature(tampered, &P256Verifier));
    // Trusted and valid, but for a head this sink never submitted.
    let earlier = log.at(0).unwrap();
    assert!(!sink.record_cosignature(cosign(&issuer, &witness, earlier, 1_500_000), &P256Verifier));
    // Trusted and valid, but attesting to another issuer's history.
    let rival = TestSigner::from_seed(7);
    let rival_log = log_with(&rival, 2);
    let for_rival = cosign(&rival, &witness, rival_log.head().unwrap(), 1_500_000);
    assert!(!sink.record_cosignature(for_rival, &P256Verifier));

    assert_eq!(sink.coverage(&digest), 0);
    assert!(!sink.status(&digest).unwrap().is_publicly_visible());
}

#[test]
fn resubmitting_a_head_does_not_discard_its_cosignatures() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();

    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![witness.public_key()], 1);
    sink.submit(head);
    sink.record_cosignature(cosign(&issuer, &witness, head, 1_500_000), &P256Verifier);
    assert!(sink.submit(head).is_publicly_visible());
    assert_eq!(sink.coverage(&head.body_digest()), 1);
}

#[test]
fn with_no_witnesses_nothing_is_ever_anchored() {
    // The honest outcome rather than a special case: no witnesses means no attestation, and
    // a threshold of zero would mean "anchored with nobody attesting".
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();

    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![], 0);
    assert_eq!(sink.min_witnesses(), 1);
    assert!(!sink.submit(head).is_publicly_visible());
    assert!(!sink
        .status(&head.body_digest())
        .unwrap()
        .is_publicly_visible());
    assert!(sink.status(&[9u8; 32]).is_none());
}

#[test]
fn a_witness_refusal_is_what_the_issuer_gets_for_a_second_head() {
    // The service-loop consequence of the whole feature: asking a witness to attest to a
    // second head at one position does not return a signature, it returns evidence against
    // the issuer. Nothing to retry around.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let reg = PromiseRegistry::new(issuer.public_key());

    let mut log_a = CheckpointLog::new(issuer.public_key());
    let mut log_b = CheckpointLog::new(issuer.public_key());
    let story_a =
        publish_with_checkpoint(&reg, &params(7), &issuer, &mut log_a).expect("publishes");
    // A second epoch-7 story: same registry, different exact-set window, so a different body.
    let mut other_params = params(7);
    other_params.valid_for_secs += 1;
    let story_b =
        publish_with_checkpoint(&reg, &other_params, &issuer, &mut log_b).expect("publishes");
    assert_ne!(
        story_a.checkpoint.body_digest(),
        story_b.checkpoint.body_digest()
    );

    let mut wlog = WitnessLog::new(witness.public_key(), issuer.public_key());
    wlog.cosign(&story_a.checkpoint, 1_500_000, &witness, &P256Verifier)
        .expect("the first head is attested");

    match wlog.cosign(&story_b.checkpoint, 1_500_100, &witness, &P256Verifier) {
        Err(WitnessRefusal::Equivocation(proof)) => {
            verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier)
                .expect("the refusal is evidence, not an opinion");
        }
        other => panic!("expected an equivocation refusal, got {other:?}"),
    }

    // And the second story can never reach anchored, because no trusted witness will sign it.
    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![witness.public_key()], 1);
    sink.submit(&story_b.checkpoint);
    assert!(!sink
        .status(&story_b.checkpoint.body_digest())
        .unwrap()
        .is_publicly_visible());
}
