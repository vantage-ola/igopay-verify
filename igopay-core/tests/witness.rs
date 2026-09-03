//! Witness cosignatures (B7): the half of anchoring an offline payee can check.
//!
//! `tests/checkpoint.rs` proves equivocation becomes *provable*. These prove it becomes
//! *refusable at the counter*: a second party attests to one head per position, its
//! signature travels with the checkpoint, and a payee with no network verifies it.
//!
//! Two properties get the most attention, because both are ways this could quietly fail:
//! a cosignature must not be usable as anything else (domain separation), and cosignatures
//! must never affect a checkpoint's identity — otherwise collecting one more signature
//! would look exactly like the issuer telling a second story.

mod common;

use common::TestSigner;
use igopay_core::checkpoint::install_checkpointed_list;
use igopay_core::crypto::{PubKeyBytes, Signer};
use igopay_core::witness::install_witnessed_list;
use igopay_core::{
    detect_equivocation, verify_checkpoint, verify_equivocation_proof, verify_witnessed, BlockList,
    Checkpoint, CheckpointError, CheckpointTracker, CheckpointVerdict, Cosignature,
    EquivocationKind, P256Verifier, SignedBlockList, WitnessLog, WitnessRefusal,
    WitnessedCheckpoint, COSIGN_DOMAIN, GENESIS_PREV, MAX_COSIGNATURES,
};

fn key(n: u32) -> PubKeyBytes {
    let mut k = [0u8; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_be_bytes());
    k
}

fn list_at(issuer: &TestSigner, epoch: u64, blocked: &[u32]) -> SignedBlockList {
    let mut list = BlockList::sized_for(blocked.len().max(1), 12);
    for n in blocked {
        list.insert(&key(*n));
        list.insert_recent(key(*n));
    }
    let mut doc = list.to_unsigned(epoch, 1_000_000 + epoch, 1_086_400 + epoch);
    doc.sig_issuer = issuer.sign_prehash(&doc.body_digest());
    doc
}

fn signed_cp(
    issuer: &TestSigner,
    seq: u64,
    epoch: u64,
    list: &SignedBlockList,
    prev_hash: [u8; 32],
) -> Checkpoint {
    let mut cp = Checkpoint {
        seq,
        epoch,
        list_digest: list.body_digest(),
        prev_hash,
        issued_at: 1_000_000 + epoch,
        sig_issuer: [0u8; 64],
    };
    cp.sig_issuer = issuer.sign_prehash(&cp.body_digest());
    cp
}

/// `n` honest publications and the honest chain over them (epoch == seq + 1).
fn honest_chain(issuer: &TestSigner, n: u64) -> (Vec<SignedBlockList>, Vec<Checkpoint>) {
    let mut lists = Vec::new();
    let mut chain: Vec<Checkpoint> = Vec::new();
    for i in 0..n {
        let list = list_at(issuer, i + 1, &[i as u32]);
        let prev = chain.last().map_or(GENESIS_PREV, |c| c.body_digest());
        let cp = signed_cp(issuer, i, i + 1, &list, prev);
        lists.push(list);
        chain.push(cp);
    }
    (lists, chain)
}

/// Cosign `cp` with a fresh witness log, returning the witnessed artefact.
fn witnessed_by(issuer: &TestSigner, witness: &TestSigner, cp: &Checkpoint) -> WitnessedCheckpoint {
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    let cosig = log
        .cosign(cp, 1_500_000, witness, &P256Verifier)
        .expect("cosigns");
    let mut wc = WitnessedCheckpoint::new(cp.clone());
    assert!(wc.attach(cosig));
    wc
}

// ---------------------------------------------------------------------------
// Wire format and identity
// ---------------------------------------------------------------------------

#[test]
fn a_witnessed_checkpoint_survives_the_wire() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let wc = witnessed_by(&issuer, &witness, &chain[0]);

    let back = WitnessedCheckpoint::from_bytes(&wc.encode()).expect("decodes");
    assert_eq!(back, wc);
    verify_witnessed(
        &back,
        &issuer.public_key(),
        &[witness.public_key()],
        &P256Verifier,
    )
    .expect("verifies");
}

#[test]
fn cosignatures_do_not_change_a_checkpoints_identity() {
    // The invariant that keeps witnessing from breaking equivocation detection. One device
    // collects a checkpoint before a witness replies, another after; both hold the SAME
    // checkpoint, and the difference must not read as the issuer telling two stories.
    let issuer = TestSigner::from_seed(1);
    let w1 = TestSigner::from_seed(2);
    let w2 = TestSigner::from_seed(3);
    let (_, chain) = honest_chain(&issuer, 1);

    let bare = WitnessedCheckpoint::new(chain[0].clone());
    let one = witnessed_by(&issuer, &w1, &chain[0]);
    let two = {
        let mut wc = one.clone();
        let mut log = WitnessLog::new(w2.public_key(), issuer.public_key());
        let cosig = log
            .cosign(&chain[0], 1_500_001, &w2, &P256Verifier)
            .unwrap();
        assert!(wc.attach(cosig));
        wc
    };

    assert_eq!(bare.checkpoint.body_digest(), one.checkpoint.body_digest());
    assert_eq!(one.checkpoint.body_digest(), two.checkpoint.body_digest());
    assert!(detect_equivocation(&bare.checkpoint, &two.checkpoint).is_none());

    // And a device that already holds the bare checkpoint sees a re-delivery, not an event.
    let mut tracker = CheckpointTracker::new(issuer.public_key(), 8);
    tracker.offer(&bare.checkpoint, &P256Verifier).unwrap();
    assert_eq!(
        tracker.offer(&two.checkpoint, &P256Verifier).unwrap(),
        CheckpointVerdict::Duplicate
    );
}

#[test]
fn the_cosignature_set_is_canonical_and_deduplicated() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let witnesses: Vec<TestSigner> = (2..6).map(TestSigner::from_seed).collect();

    // Attach in one order, then the reverse; the encodings must match.
    let mut a = WitnessedCheckpoint::new(chain[0].clone());
    let mut b = WitnessedCheckpoint::new(chain[0].clone());
    for w in &witnesses {
        let mut log = WitnessLog::new(w.public_key(), issuer.public_key());
        a.attach(log.cosign(&chain[0], 1_500_000, w, &P256Verifier).unwrap());
    }
    for w in witnesses.iter().rev() {
        let mut log = WitnessLog::new(w.public_key(), issuer.public_key());
        b.attach(log.cosign(&chain[0], 1_500_000, w, &P256Verifier).unwrap());
    }
    assert_eq!(a.encode(), b.encode());
    assert_eq!(a.cosignatures.len(), 4);

    // Re-attaching the same witness replaces rather than doubling: coverage counts
    // witnesses, not signatures.
    let mut log = WitnessLog::new(witnesses[0].public_key(), issuer.public_key());
    let again = log
        .cosign(&chain[0], 1_600_000, &witnesses[0], &P256Verifier)
        .unwrap();
    a.attach(again);
    assert_eq!(a.cosignatures.len(), 4);
}

#[test]
fn a_repeated_witness_on_the_wire_is_refused() {
    // Hand-built rather than produced by `attach`: a hostile issuer could repeat one
    // cosignature to make a single witness look like four.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let wc = witnessed_by(&issuer, &witness, &chain[0]);

    let doubled = WitnessedCheckpoint {
        checkpoint: chain[0].clone(),
        cosignatures: vec![wc.cosignatures[0].clone(), wc.cosignatures[0].clone()],
    };
    assert_eq!(
        verify_witnessed(
            &doubled,
            &issuer.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::CosignaturesNotSorted
    );
}

#[test]
fn too_many_cosignatures_is_refused_by_the_decoder() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut wc = WitnessedCheckpoint::new(chain[0].clone());
    for seed in 2..(2 + MAX_COSIGNATURES as u8 + 1) {
        let w = TestSigner::from_seed(seed);
        let mut log = WitnessLog::new(w.public_key(), issuer.public_key());
        wc.attach(log.cosign(&chain[0], 1_500_000, &w, &P256Verifier).unwrap());
    }
    assert!(wc.cosignatures.len() > MAX_COSIGNATURES);
    assert!(WitnessedCheckpoint::from_bytes(&wc.encode()).is_err());
}

// ---------------------------------------------------------------------------
// Domain separation — the reason a cosignature is not signed over the raw digest
// ---------------------------------------------------------------------------

#[test]
fn a_cosignature_is_not_a_valid_issuer_signature() {
    // The concrete attack this closes: if a witness signed the checkpoint's body digest
    // directly, its signature would be over the *identical message* the issuer signs. Any
    // key serving both roles — a reused device key, a witness later promoted — would make
    // every cosignature a valid issuer signature, and the witness could mint history.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);

    // One signer wearing both hats, which is exactly the hygiene failure we refuse to
    // depend on.
    let both = TestSigner::from_seed(2);
    let mut log = WitnessLog::new(both.public_key(), issuer.public_key());
    let cosig = log
        .cosign(&chain[0], 1_500_000, &both, &P256Verifier)
        .expect("cosigns");

    // Take the cosignature and try to pass it off as the issuer signature on a checkpoint
    // "issued" by that same key.
    let mut forged = Checkpoint {
        seq: 0,
        epoch: 1,
        list_digest: lists[0].body_digest(),
        prev_hash: GENESIS_PREV,
        issued_at: 1_000_001,
        sig_issuer: cosig.sig_witness,
    };
    assert_eq!(
        verify_checkpoint(&forged, &both.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadIssuerSignature
    );

    // And the same in reverse: an issuer signature is not a cosignature.
    forged.sig_issuer = both.sign_prehash(&forged.body_digest());
    let borrowed = Cosignature {
        witness_pubkey: both.public_key(),
        issuer_pubkey: both.public_key(),
        checkpoint_digest: forged.body_digest(),
        signed_at: 1_500_000,
        sig_witness: forged.sig_issuer,
    };
    assert_eq!(
        borrowed.verify(&P256Verifier).unwrap_err(),
        CheckpointError::BadWitnessSignature
    );
}

#[test]
fn the_signing_digest_is_the_tagged_hash() {
    // Pin the construction, because two implementations that disagree here produce
    // signatures neither can verify, and the tag is not on the wire to remind them.
    use sha2::{Digest, Sha256};
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let wc = witnessed_by(&issuer, &witness, &chain[0]);
    let cosig = &wc.cosignatures[0];

    let mut h = Sha256::new();
    h.update(COSIGN_DOMAIN);
    h.update(cosig.encode_body());
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(cosig.signing_digest(), expected);
    assert_ne!(cosig.signing_digest(), chain[0].body_digest());
}

// ---------------------------------------------------------------------------
// Verification and coverage
// ---------------------------------------------------------------------------

#[test]
fn coverage_counts_trusted_witnesses_and_ignores_strangers() {
    let issuer = TestSigner::from_seed(1);
    let known = TestSigner::from_seed(2);
    let stranger = TestSigner::from_seed(3);
    let (_, chain) = honest_chain(&issuer, 1);

    let mut wc = witnessed_by(&issuer, &known, &chain[0]);
    let mut other = WitnessLog::new(stranger.public_key(), issuer.public_key());
    wc.attach(
        other
            .cosign(&chain[0], 1_500_000, &stranger, &P256Verifier)
            .unwrap(),
    );

    let coverage = verify_witnessed(
        &wc,
        &issuer.public_key(),
        &[known.public_key()],
        &P256Verifier,
    )
    .expect("verifies");
    assert_eq!(coverage.witnesses, 1);
    assert_eq!(coverage.unknown, 1);
    assert!(coverage.is_witnessed());

    // A device that trusts nobody gets an honest zero rather than an error: the unwitnessed
    // path still works, it just carries less assurance.
    let none = verify_witnessed(&wc, &issuer.public_key(), &[], &P256Verifier).expect("verifies");
    assert_eq!(none.witnesses, 0);
    assert_eq!(none.unknown, 2);
    assert!(!none.is_witnessed());
}

#[test]
fn a_bad_signature_from_a_trusted_witness_is_loud() {
    // Not a silent zero. Either the artefact was tampered with or that key is compromised,
    // and both deserve to stop the install.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut wc = witnessed_by(&issuer, &witness, &chain[0]);
    wc.cosignatures[0].sig_witness[10] ^= 0xff;

    assert_eq!(
        verify_witnessed(
            &wc,
            &issuer.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::BadWitnessSignature
    );
}

#[test]
fn a_malleated_cosignature_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut wc = witnessed_by(&issuer, &witness, &chain[0]);
    wc.cosignatures[0].sig_witness = TestSigner::malleate(&wc.cosignatures[0].sig_witness);

    assert_eq!(
        verify_witnessed(
            &wc,
            &issuer.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::MalleableSignature
    );
}

#[test]
fn a_cosignature_cannot_be_moved_to_another_checkpoint() {
    // It names the checkpoint it signed, so lifting a witness's attestation off position 0
    // and stapling it to position 1 fails structurally, before any curve work.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 2);
    let wc = witnessed_by(&issuer, &witness, &chain[0]);

    let mut lifted = WitnessedCheckpoint::new(chain[1].clone());
    assert!(
        !lifted.attach(wc.cosignatures[0].clone()),
        "attach must refuse a cosignature for a different checkpoint"
    );

    // Forced on by hand, it is still refused on verify.
    let stapled = WitnessedCheckpoint {
        checkpoint: chain[1].clone(),
        cosignatures: vec![wc.cosignatures[0].clone()],
    };
    assert_eq!(
        verify_witnessed(
            &stapled,
            &issuer.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::CosignatureForAnotherCheckpoint
    );
}

#[test]
fn a_cosignature_cannot_be_moved_to_another_issuers_history() {
    // Found by a test that was meant to prove something else, which is the good kind of
    // accident. A checkpoint's body carries no issuer identity, so two issuers publishing the
    // same list at the same position produce BYTE-IDENTICAL checkpoint bodies — trivially so
    // for an empty list at genesis. A cosignature naming only the digest would therefore fit
    // both, letting any issuer staple a rival's attestation onto its own history, and making a
    // witness that watches both look like it signed two heads at one position. The cosignature
    // names the issuer for exactly this reason.
    let issuer_a = TestSigner::from_seed(1);
    let issuer_b = TestSigner::from_seed(5);
    let witness = TestSigner::from_seed(2);

    // Same list content, same position, same times: identical bodies, different signatures.
    let list_a = list_at(&issuer_a, 1, &[]);
    let list_b = list_at(&issuer_b, 1, &[]);
    let cp_a = signed_cp(&issuer_a, 0, 1, &list_a, GENESIS_PREV);
    let cp_b = signed_cp(&issuer_b, 0, 1, &list_b, GENESIS_PREV);
    assert_eq!(
        cp_a.body_digest(),
        cp_b.body_digest(),
        "this vector is only meaningful if the bodies collide"
    );
    assert_ne!(cp_a.sig_issuer, cp_b.sig_issuer);

    let wc_a = witnessed_by(&issuer_a, &witness, &cp_a);
    // The digest matches, so `attach` accepts it — the issuer check cannot live there,
    // because a checkpoint does not know whose it is.
    let mut stapled = WitnessedCheckpoint::new(cp_b.clone());
    assert!(stapled.attach(wc_a.cosignatures[0].clone()));

    assert_eq!(
        verify_witnessed(
            &stapled,
            &issuer_b.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::CosignatureForAnotherIssuer
    );
    // Under the issuer it was actually made for, it stands.
    assert_eq!(
        verify_witnessed(
            &wc_a,
            &issuer_a.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .expect("verifies")
        .witnesses,
        1
    );
}

#[test]
fn a_witnessed_checkpoint_from_a_rival_issuer_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(9);
    let witness = TestSigner::from_seed(2);
    let (_, theirs) = honest_chain(&rival, 1);
    let wc = witnessed_by(&rival, &witness, &theirs[0]);

    assert_eq!(
        verify_witnessed(
            &wc,
            &issuer.public_key(),
            &[witness.public_key()],
            &P256Verifier
        )
        .unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

// ---------------------------------------------------------------------------
// The witness's one rule
// ---------------------------------------------------------------------------

#[test]
fn a_witness_cosigns_an_honest_chain_end_to_end() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 5);
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());

    for cp in &chain {
        let cosig = log
            .cosign(cp, 1_500_000 + cp.seq, &witness, &P256Verifier)
            .expect("cosigns");
        assert_eq!(cosig.checkpoint_digest, cp.body_digest());
        cosig.verify(&P256Verifier).expect("verifies");
    }
    assert_eq!(log.len(), 5);
    assert_eq!(log.checkpoint_at(3), Some(&chain[3]));
    assert!(log.cosignature_at(4).is_some());
    assert!(log.cosignature_at(9).is_none());
}

#[test]
fn a_witness_refuses_a_second_head_at_one_position_and_hands_back_the_proof() {
    // The whole mechanism, in one test. The issuer asks the witness to attest to a second
    // epoch-1 list at position 0 — and instead of a signature it gets evidence.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (lists, chain) = honest_chain(&issuer, 1);
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    log.cosign(&chain[0], 1_500_000, &witness, &P256Verifier)
        .expect("cosigns the first");

    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let shadow = signed_cp(&issuer, 0, other.epoch, &other, GENESIS_PREV);

    match log.cosign(&shadow, 1_500_100, &witness, &P256Verifier) {
        Err(WitnessRefusal::Equivocation(proof)) => {
            assert_eq!(proof.kind(), Some(EquivocationKind::DuplicatePosition));
            igopay_core::verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier)
                .expect("the proof stands on its own");
        }
        other => panic!("expected an equivocation refusal, got {other:?}"),
    }

    // The witness keeps what it signed and issues nothing new.
    assert_eq!(log.len(), 1);
    assert_eq!(log.checkpoint_at(0), Some(&chain[0]));

    // And it can answer the same question offline, for a payee that turns up with the other
    // story in hand.
    assert!(log.conflicting(&shadow).is_some());
    assert!(log.conflicting(&chain[0]).is_none());
}

#[test]
fn cosigning_is_idempotent() {
    // The artefact a device ends up holding must not depend on how many times the issuer
    // asked. A fresh signature each time would also churn the distribution for no reason.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());

    let first = log
        .cosign(&chain[0], 1_500_000, &witness, &P256Verifier)
        .unwrap();
    let again = log
        .cosign(&chain[0], 1_900_000, &witness, &P256Verifier)
        .unwrap();
    assert_eq!(first, again);
    assert_eq!(log.len(), 1);
}

#[test]
fn a_witness_will_not_cosign_what_the_issuer_did_not_sign() {
    let issuer = TestSigner::from_seed(1);
    let liar = TestSigner::from_seed(8);
    let witness = TestSigner::from_seed(2);
    let (lists, _) = honest_chain(&liar, 1);
    let fake = signed_cp(&liar, 0, 1, &lists[0], GENESIS_PREV);

    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    assert_eq!(
        log.cosign(&fake, 1_500_000, &witness, &P256Verifier)
            .unwrap_err(),
        WitnessRefusal::Unusable(CheckpointError::BadIssuerSignature)
    );
    assert!(log.is_empty());
}

#[test]
fn a_witness_will_not_cosign_across_a_broken_link() {
    // A witness that attested to a chain that does not join up would be attesting to
    // nothing. Reusing the tracker's comparison is what gets this for free.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    log.cosign(&chain[0], 1_500_000, &witness, &P256Verifier)
        .unwrap();

    let unlinked = signed_cp(&issuer, 1, 2, &list_at(&issuer, 2, &[7]), [8u8; 32]);
    assert!(matches!(
        log.cosign(&unlinked, 1_500_100, &witness, &P256Verifier),
        Err(WitnessRefusal::Equivocation(_))
    ));
    assert_eq!(log.len(), 1);
}

#[test]
fn a_witness_refuses_to_sign_under_the_wrong_key() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let impostor = TestSigner::from_seed(3);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());

    assert_eq!(
        log.cosign(&chain[0], 1_500_000, &impostor, &P256Verifier)
            .unwrap_err(),
        WitnessRefusal::Unusable(CheckpointError::BadWitnessSignature)
    );
    assert!(log.is_empty());
}

// ---------------------------------------------------------------------------
// The device-side install path
// ---------------------------------------------------------------------------

#[test]
fn a_witnessed_list_installs_and_reports_its_coverage() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let list = list_at(&issuer, 5, &[11, 12]);
    let cp = signed_cp(&issuer, 0, 5, &list, GENESIS_PREV);
    let wc = witnessed_by(&issuer, &witness, &cp);

    let (installed, coverage) = install_witnessed_list(
        &list,
        &wc,
        &issuer.public_key(),
        &[witness.public_key()],
        &P256Verifier,
        None,
    )
    .expect("installs");
    assert_eq!(installed.epoch(), 5);
    assert!(installed.contains_exact(&key(11)));
    assert_eq!(coverage.witnesses, 1);
}

#[test]
fn the_witnessed_path_weakens_no_block_list_rule() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let list = list_at(&issuer, 5, &[11]);
    let cp = signed_cp(&issuer, 0, 5, &list, GENESIS_PREV);
    let wc = witnessed_by(&issuer, &witness, &cp);
    let trusted = [witness.public_key()];

    // Rollback guard.
    assert!(matches!(
        install_witnessed_list(
            &list,
            &wc,
            &issuer.public_key(),
            &trusted,
            &P256Verifier,
            Some(9)
        )
        .unwrap_err(),
        CheckpointError::List(_)
    ));

    // Commitment: a different epoch-5 list, cosigned head and all, is still refused.
    let other = list_at(&issuer, 5, &[4242]);
    assert_eq!(
        install_witnessed_list(
            &other,
            &wc,
            &issuer.public_key(),
            &trusted,
            &P256Verifier,
            None
        )
        .unwrap_err(),
        CheckpointError::ListNotCommitted
    );

    // A witness cannot rescue a checkpoint the issuer did not sign.
    let rival = TestSigner::from_seed(9);
    let forged = signed_cp(&rival, 0, 5, &list, GENESIS_PREV);
    let forged_wc = witnessed_by(&rival, &witness, &forged);
    assert_eq!(
        install_witnessed_list(
            &list,
            &forged_wc,
            &issuer.public_key(),
            &trusted,
            &P256Verifier,
            None
        )
        .unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

#[test]
fn an_unwitnessed_checkpoint_still_installs() {
    // A witness outage must not stop revocation reaching devices: refusing would leave them
    // on an older block list that blocks fewer cheaters. Coverage is reported, not enforced.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let list = list_at(&issuer, 5, &[11]);
    let cp = signed_cp(&issuer, 0, 5, &list, GENESIS_PREV);
    let bare = WitnessedCheckpoint::new(cp.clone());

    let (installed, coverage) = install_witnessed_list(
        &list,
        &bare,
        &issuer.public_key(),
        &[witness.public_key()],
        &P256Verifier,
        None,
    )
    .expect("installs");
    assert!(installed.contains(&key(11)));
    assert!(!coverage.is_witnessed());

    // Same artefact through the unwitnessed path, for a deployment with no witness at all.
    install_checkpointed_list(&list, &cp, &issuer.public_key(), &P256Verifier, None)
        .expect("installs");
}

#[test]
fn a_split_view_cannot_get_two_heads_witnessed() {
    // End to end, and the reason this is worth building: the issuer produces two epoch-7
    // stories. Both install unwitnessed. Only ONE can carry the witness's signature, so the
    // device offered the unwitnessed one can tell the difference at the counter, with no
    // network — and the attempt to get the second one signed produced evidence.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let blocks_them = list_at(&issuer, 7, &[42]);
    let does_not = list_at(&issuer, 7, &[]);
    let story_a = signed_cp(&issuer, 0, 7, &blocks_them, GENESIS_PREV);
    let story_b = signed_cp(&issuer, 0, 7, &does_not, GENESIS_PREV);
    let trusted = [witness.public_key()];

    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    let cosig_a = log
        .cosign(&story_a, 1_500_000, &witness, &P256Verifier)
        .expect("the first story is witnessed");
    let refusal = log.cosign(&story_b, 1_500_100, &witness, &P256Verifier);
    assert!(matches!(refusal, Err(WitnessRefusal::Equivocation(_))));

    let mut wc_a = WitnessedCheckpoint::new(story_a.clone());
    wc_a.attach(cosig_a);
    let wc_b = WitnessedCheckpoint::new(story_b.clone());

    let (_, cov_a) = install_witnessed_list(
        &blocks_them,
        &wc_a,
        &issuer.public_key(),
        &trusted,
        &P256Verifier,
        None,
    )
    .expect("installs");
    let (_, cov_b) = install_witnessed_list(
        &does_not,
        &wc_b,
        &issuer.public_key(),
        &trusted,
        &P256Verifier,
        None,
    )
    .expect("installs");

    assert!(cov_a.is_witnessed());
    assert!(
        !cov_b.is_witnessed(),
        "the second story must not be able to carry attestation"
    );
}

// ---------------------------------------------------------------------------
// Surviving a restart
//
// A witness whose memory ended with its process would be a witness whose one rule could be
// defeated by asking it to reboot. These are the tests that make persistence real: the state
// goes out, comes back, and the rule still holds — and nothing that comes back in is trusted
// for having been stored.
// ---------------------------------------------------------------------------

/// Round-trip a witness through its persisted form, the way a file-backed one does.
fn restart(log: &WitnessLog, witness: &TestSigner, issuer: &TestSigner) -> WitnessLog {
    let seen: Vec<Checkpoint> = log.seen().cloned().collect();
    let issued: Vec<Cosignature> = log.issued().cloned().collect();
    WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &seen,
        &issued,
        &P256Verifier,
    )
    .expect("resumes")
}

#[test]
fn a_resumed_witness_hands_back_the_cosignature_it_already_issued() {
    // The bytes a device holds must not depend on whether the witness has restarted since.
    // If resume lost the issued set, this would mint a second cosignature — verifiable, but
    // different, so two payees comparing artefacts would see a difference the issuer did not
    // create.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 3);

    let mut before = WitnessLog::new(witness.public_key(), issuer.public_key());
    let originals: Vec<Cosignature> = chain
        .iter()
        .map(|cp| {
            before
                .cosign(cp, 1_500_000 + cp.seq, &witness, &P256Verifier)
                .expect("cosigns")
        })
        .collect();

    let mut after = restart(&before, &witness, &issuer);
    assert_eq!(after.len(), 3);
    for (cp, original) in chain.iter().zip(&originals) {
        assert_eq!(after.cosignature_at(cp.seq), Some(original));
        assert_eq!(after.checkpoint_at(cp.seq), Some(cp));
        // Asked again, it re-states rather than re-signs.
        let again = after
            .cosign(cp, 9_999_999, &witness, &P256Verifier)
            .expect("cosigns");
        assert_eq!(
            &again, original,
            "a restarted witness must not issue a second, different cosignature"
        );
    }
}

#[test]
fn a_resumed_witness_still_refuses_a_second_head_at_a_position_it_cosigned() {
    // The load-bearing one. Restarting must not reopen a position: the rule is "at most one
    // head per position, EVER", and ever has to survive a power cut.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (lists, chain) = honest_chain(&issuer, 2);

    let mut before = WitnessLog::new(witness.public_key(), issuer.public_key());
    for cp in &chain {
        before
            .cosign(cp, 1_500_000 + cp.seq, &witness, &P256Verifier)
            .expect("cosigns");
    }
    let mut after = restart(&before, &witness, &issuer);

    // A different epoch-2 list, re-signed at position 1: the same story the issuer would tell
    // a second device.
    let other = list_at(&issuer, 2, &[77]);
    assert_ne!(other.body_digest(), lists[1].body_digest());
    let second_story = signed_cp(&issuer, 1, 2, &other, chain[0].body_digest());

    match after.cosign(&second_story, 1_600_000, &witness, &P256Verifier) {
        Err(WitnessRefusal::Equivocation(proof)) => {
            assert_eq!(proof.kind(), Some(EquivocationKind::DuplicatePosition));
            verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier)
                .expect("the refusal is portable evidence, not an opinion");
        }
        other => panic!("a resumed witness must refuse a second head: {other:?}"),
    }
    // And it did not quietly adopt it.
    assert_eq!(after.checkpoint_at(1), Some(&chain[1]));
}

#[test]
fn resuming_from_a_self_contradictory_state_is_a_refusal_with_a_proof() {
    // If two heads at one position ever reach the state file, loading it must not average
    // them into a view: the file itself is evidence, and the operator needs to be told so.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, 1, &[99]);
    let twin = signed_cp(&issuer, 0, 1, &other, GENESIS_PREV);

    match WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &[chain[0].clone(), twin],
        &[],
        &P256Verifier,
    ) {
        Err(WitnessRefusal::Equivocation(proof)) => {
            verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier)
                .expect("proof verifies");
        }
        other => panic!("expected an equivocation refusal, got {other:?}"),
    }
}

#[test]
fn a_tampered_state_file_is_refused_at_load_rather_than_signed_on_top_of() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut forged = chain[0].clone();
    forged.epoch = 9; // body changed, signature not re-made

    let err = WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &[forged],
        &[],
        &P256Verifier,
    )
    .expect_err("must refuse");
    assert_eq!(
        err,
        WitnessRefusal::Unusable(CheckpointError::BadIssuerSignature)
    );
}

#[test]
fn resume_refuses_a_cosignature_that_is_not_this_witnesss_own_work() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let stranger = TestSigner::from_seed(3);
    let (_, chain) = honest_chain(&issuer, 1);

    let mut theirs = WitnessLog::new(stranger.public_key(), issuer.public_key());
    let cosig = theirs
        .cosign(&chain[0], 1_500_000, &stranger, &P256Verifier)
        .expect("cosigns");

    // Valid, and none of this witness's business. Adopting it would let the witness's own
    // state claim a position it never actually attested to.
    let err = WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &chain,
        &[cosig],
        &P256Verifier,
    )
    .expect_err("must refuse");
    assert_eq!(
        err,
        WitnessRefusal::Unusable(CheckpointError::BadWitnessSignature)
    );
}

#[test]
fn resume_refuses_a_cosignature_for_a_checkpoint_it_no_longer_holds() {
    // A witness holding a signature without the thing it signed cannot produce a proof at
    // that position — it would have a statement it can no longer defend. Refuse at load, so
    // the operator finds out from a tool rather than from a dispute.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 2);

    let mut before = WitnessLog::new(witness.public_key(), issuer.public_key());
    for cp in &chain {
        before
            .cosign(cp, 1_500_000 + cp.seq, &witness, &P256Verifier)
            .expect("cosigns");
    }
    let issued: Vec<Cosignature> = before.issued().cloned().collect();

    let err = WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &chain[..1], // position 1's checkpoint went missing
        &issued,
        &P256Verifier,
    )
    .expect_err("must refuse");
    assert_eq!(
        err,
        WitnessRefusal::Unusable(CheckpointError::CosignatureForAnotherCheckpoint)
    );
}

#[test]
fn resume_refuses_a_cosignature_aimed_at_another_issuers_history() {
    // The `issuer_pubkey` field earning its place again: two issuers publishing the same
    // list at the same position produce byte-identical checkpoint bodies.
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(4);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);

    // Built directly: the rival never signed this checkpoint, so no WitnessLog watching the
    // rival would ever hand one out. That is the point — the attacker is the one assembling
    // the state file, and the loader has to be the thing that says no.
    let mut cosig = Cosignature {
        witness_pubkey: witness.public_key(),
        issuer_pubkey: rival.public_key(),
        checkpoint_digest: chain[0].body_digest(),
        signed_at: 1_500_000,
        sig_witness: [0u8; 64],
    };
    cosig.sig_witness = witness.sign_prehash(&cosig.signing_digest());
    cosig.verify(&P256Verifier).expect("genuinely signed");

    let err = WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &chain,
        &[cosig],
        &P256Verifier,
    )
    .expect_err("must refuse");
    assert_eq!(
        err,
        WitnessRefusal::Unusable(CheckpointError::CosignatureForAnotherIssuer)
    );
}

#[test]
fn resume_keeps_the_first_cosignature_when_a_position_has_two() {
    // Two valid statements about the same head are the same statement. Keeping the earliest
    // makes a restored witness agree with whatever was distributed first.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 1);

    let mut log = WitnessLog::new(witness.public_key(), issuer.public_key());
    let first = log
        .cosign(&chain[0], 1_500_000, &witness, &P256Verifier)
        .expect("cosigns");
    let mut later = first.clone();
    later.signed_at = 1_600_000;
    later.sig_witness = witness.sign_prehash(&later.signing_digest());
    assert_ne!(first, later);

    let resumed = WitnessLog::resume(
        witness.public_key(),
        issuer.public_key(),
        &chain,
        &[first.clone(), later],
        &P256Verifier,
    )
    .expect("resumes");
    assert_eq!(resumed.cosignature_at(0), Some(&first));
}

#[test]
fn a_resumed_witness_can_still_prove_a_conflict_it_was_shown_offline() {
    // The dispute path across a restart: a payee walks up with a head, and the witness that
    // rebooted last week still turns it into two of the issuer's own signatures.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&issuer, 3);

    let mut before = WitnessLog::new(witness.public_key(), issuer.public_key());
    for cp in &chain {
        before
            .cosign(cp, 1_500_000 + cp.seq, &witness, &P256Verifier)
            .expect("cosigns");
    }
    let after = restart(&before, &witness, &issuer);

    let other = list_at(&issuer, 3, &[123]);
    let foreign = signed_cp(&issuer, 2, 3, &other, chain[1].body_digest());
    let proof = after
        .conflicting(&foreign)
        .expect("a head nobody else was shown");
    verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).expect("proof verifies");

    // And an honest head it already knows is not a conflict.
    assert!(after.conflicting(&chain[2]).is_none());
}
