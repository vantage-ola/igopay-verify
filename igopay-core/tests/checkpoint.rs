//! Checkpoints (B7): the issuer's own history, and what makes it undeniable.
//!
//! The block-list tests (`tests/blocklist.rs`) prove a device refuses a *forged* or
//! *replayed* list. These prove something the signature alone cannot: that the issuer
//! cannot tell two devices two different stories and get away with it. So most of what
//! follows is about pairs of artefacts — one honest, one from the other story — and about
//! the pairs that must NOT be mistaken for evidence, because a false accusation against
//! the issuer is as damaging as an undetected real one.

mod common;

use common::TestSigner;
use igopay_core::checkpoint::{install_checkpointed_list, verify_list_commitment};
use igopay_core::crypto::{PubKeyBytes, Signer};
use igopay_core::{
    classify_checkpoint, detect_equivocation, verify_chain_link, verify_checkpoint,
    verify_equivocation_proof, BlockList, BlockListError, Checkpoint, CheckpointError,
    CheckpointTracker, CheckpointVerdict, EquivocationKind, EquivocationProof, Hash, P256Verifier,
    SignedBlockList, GENESIS_PREV,
};

/// Synthesize a distinct 33-byte payer key, as `tests/blocklist.rs` does: the filter
/// hashes raw bytes and never parses a curve point.
fn key(n: u32) -> PubKeyBytes {
    let mut k = [0u8; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_be_bytes());
    k
}

/// A signed block list at `epoch` blocking `blocked`.
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
    list_digest: Hash,
    prev_hash: Hash,
) -> Checkpoint {
    let mut cp = Checkpoint {
        seq,
        epoch,
        list_digest,
        prev_hash,
        issued_at: 1_000_000 + epoch,
        sig_issuer: [0u8; 64],
    };
    cp.sig_issuer = issuer.sign_prehash(&cp.body_digest());
    cp
}

/// The first entry in a log, committing to `list`.
fn genesis(issuer: &TestSigner, list: &SignedBlockList) -> Checkpoint {
    signed_cp(issuer, 0, list.epoch, list.body_digest(), GENESIS_PREV)
}

/// The next entry after `prev`, committing to `list`.
fn append(issuer: &TestSigner, prev: &Checkpoint, list: &SignedBlockList) -> Checkpoint {
    signed_cp(
        issuer,
        prev.seq + 1,
        list.epoch,
        list.body_digest(),
        prev.body_digest(),
    )
}

/// `n` honest publications and the honest chain over them. Epochs are `1..=n`, so epoch
/// and position deliberately differ (`epoch == seq + 1`) and a test that confuses them
/// fails.
fn honest_chain(issuer: &TestSigner, n: u64) -> (Vec<SignedBlockList>, Vec<Checkpoint>) {
    let mut lists = Vec::new();
    let mut chain: Vec<Checkpoint> = Vec::new();
    for i in 0..n {
        let list = list_at(issuer, i + 1, &[i as u32]);
        let cp = match chain.last() {
            None => genesis(issuer, &list),
            Some(prev) => append(issuer, prev, &list),
        };
        lists.push(list);
        chain.push(cp);
    }
    (lists, chain)
}

fn refs(chain: &[Checkpoint]) -> Vec<&Checkpoint> {
    chain.iter().collect()
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

#[test]
fn round_trip_preserves_every_field() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 3);
    for cp in &chain {
        let back = Checkpoint::from_bytes(&cp.encode()).expect("decodes");
        assert_eq!(&back, cp);
    }
}

#[test]
fn decode_rejects_trailing_bytes() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut bytes = chain[0].encode();
    bytes.push(0x00);
    assert!(Checkpoint::from_bytes(&bytes).is_err());
}

#[test]
fn identity_is_the_body_not_the_signature() {
    // A re-signed but otherwise identical checkpoint is the SAME checkpoint. If identity
    // included the signature, an issuer re-signing its own history — or an ECDSA nonce
    // differing between two runs — would look like equivocation.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let resigned = signed_cp(
        &issuer,
        0,
        lists[0].epoch,
        lists[0].body_digest(),
        GENESIS_PREV,
    );
    assert_eq!(chain[0].body_digest(), resigned.body_digest());
    assert!(detect_equivocation(&chain[0], &resigned).is_none());
}

// ---------------------------------------------------------------------------
// Well-formedness and signatures
// ---------------------------------------------------------------------------

#[test]
fn an_honest_checkpoint_verifies() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 2);
    for cp in &chain {
        verify_checkpoint(cp, &issuer.public_key(), &P256Verifier).expect("verifies");
    }
}

#[test]
fn genesis_must_carry_the_zero_prev_hash() {
    let issuer = TestSigner::from_seed(1);
    let list = list_at(&issuer, 1, &[7]);
    let cp = signed_cp(&issuer, 0, 1, list.body_digest(), [9u8; 32]);
    assert_eq!(
        verify_checkpoint(&cp, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadGenesis
    );
}

#[test]
fn a_later_position_must_not_claim_genesis() {
    // Otherwise a device could be handed an unlinked "start of history" at position 40 and
    // treat it as the beginning of a chain, which is a free rewrite.
    let issuer = TestSigner::from_seed(1);
    let list = list_at(&issuer, 41, &[7]);
    let cp = signed_cp(&issuer, 40, 41, list.body_digest(), GENESIS_PREV);
    assert_eq!(
        verify_checkpoint(&cp, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadGenesis
    );
}

#[test]
fn a_rival_issuers_checkpoint_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(2);
    let (_, chain) = honest_chain(&rival, 1);
    assert_eq!(
        verify_checkpoint(&chain[0], &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

#[test]
fn tampering_with_the_committed_list_breaks_the_signature() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut cp = chain[0].clone();
    cp.list_digest[0] ^= 0xff;
    assert_eq!(
        verify_checkpoint(&cp, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

#[test]
fn a_malleated_signature_is_refused() {
    // The sharp one. A high-S copy of an honest checkpoint verifies fine as ECDSA, so
    // without this rule an attacker could take one honest checkpoint, malleate it, and
    // present the pair as "two signed checkpoints" — evidence against an issuer that did
    // nothing. Rejected structurally, in both the single-checkpoint and proof paths.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut malleated = chain[0].clone();
    malleated.sig_issuer = TestSigner::malleate(&chain[0].sig_issuer);
    assert_eq!(
        verify_checkpoint(&malleated, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::MalleableSignature
    );
}

#[test]
fn a_malleated_copy_is_not_evidence_of_equivocation() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut malleated = chain[0].clone();
    malleated.sig_issuer = TestSigner::malleate(&chain[0].sig_issuer);

    // Structurally: same body, so not a fork of the log at all.
    assert!(detect_equivocation(&chain[0], &malleated).is_none());

    // And a hand-built proof out of the pair convinces nobody.
    let forged = EquivocationProof {
        a: chain[0].clone(),
        b: malleated,
    };
    assert_eq!(
        verify_equivocation_proof(&forged, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::NotEquivocation
    );
}

// ---------------------------------------------------------------------------
// Chain links
// ---------------------------------------------------------------------------

#[test]
fn an_honest_chain_links_end_to_end() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 6);
    for w in chain.windows(2) {
        verify_chain_link(&w[0], &w[1], &issuer.public_key(), &P256Verifier).expect("links");
    }
}

#[test]
fn a_link_must_advance_the_position_by_exactly_one() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 3);
    assert_eq!(
        verify_chain_link(&chain[0], &chain[2], &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::PositionNotAdjacent { prev: 0, next: 2 }
    );
}

#[test]
fn a_link_must_name_its_predecessor() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 2);
    // Position 1 re-signed to point at nothing in particular.
    let orphan = signed_cp(
        &issuer,
        1,
        lists[1].epoch,
        lists[1].body_digest(),
        [3u8; 32],
    );
    assert!(matches!(
        verify_chain_link(&chain[0], &orphan, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::ChainBroken { .. }
    ));
}

#[test]
fn a_link_must_advance_the_epoch() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    // Position 1, correctly linked, but republishing the SAME epoch: exactly the hole B7
    // exists to close, seen from the chain-link side.
    let same_epoch = append(&issuer, &chain[0], &list_at(&issuer, lists[0].epoch, &[99]));
    assert_eq!(
        verify_chain_link(&chain[0], &same_epoch, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::EpochNotAdvancing { prev: 1, next: 1 }
    );
}

// ---------------------------------------------------------------------------
// Binding a checkpoint to the list it commits to
// ---------------------------------------------------------------------------

#[test]
fn a_checkpoint_commits_to_its_own_list() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 2);
    verify_list_commitment(&lists[1], &chain[1]).expect("commits");
}

#[test]
fn a_different_list_at_the_same_epoch_is_not_committed() {
    // THE hole, stated as plainly as it can be: the issuer hands device B a different
    // epoch-1 list. Device B's checkpoint does not commit to it, so B refuses the list
    // instead of quietly holding a second history.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    assert_ne!(other.body_digest(), lists[0].body_digest());
    assert_eq!(
        verify_list_commitment(&other, &chain[0]).unwrap_err(),
        CheckpointError::ListNotCommitted
    );
}

#[test]
fn the_right_list_at_the_wrong_epoch_is_not_committed() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 2);
    assert_eq!(
        verify_list_commitment(&lists[0], &chain[1]).unwrap_err(),
        CheckpointError::ListNotCommitted
    );
}

#[test]
fn a_checkpointed_list_installs_and_still_blocks() {
    let issuer = TestSigner::from_seed(1);
    let list = list_at(&issuer, 5, &[11, 12]);
    let cp = signed_cp(&issuer, 0, 5, list.body_digest(), GENESIS_PREV);

    let installed =
        install_checkpointed_list(&list, &cp, &issuer.public_key(), &P256Verifier, None)
            .expect("installs");
    assert_eq!(installed.epoch(), 5);
    assert!(installed.contains_exact(&key(11)));
    assert!(!installed.contains(&key(13)));
}

#[test]
fn install_refuses_a_list_whose_checkpoint_is_forged() {
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(2);
    let list = list_at(&issuer, 5, &[11]);
    let cp = signed_cp(&rival, 0, 5, list.body_digest(), GENESIS_PREV);
    assert_eq!(
        install_checkpointed_list(&list, &cp, &issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

#[test]
fn install_still_refuses_a_rolled_back_epoch() {
    // The checkpointed path must not weaken any block-list rule. A device holding epoch 9
    // refuses an epoch-5 list even though its checkpoint is perfectly valid.
    let issuer = TestSigner::from_seed(1);
    let list = list_at(&issuer, 5, &[11]);
    let cp = signed_cp(&issuer, 0, 5, list.body_digest(), GENESIS_PREV);
    assert_eq!(
        install_checkpointed_list(&list, &cp, &issuer.public_key(), &P256Verifier, Some(9))
            .unwrap_err(),
        CheckpointError::List(BlockListError::StaleEpoch {
            current: 9,
            offered: 5
        })
    );
}

// ---------------------------------------------------------------------------
// Equivocation: the three rules
// ---------------------------------------------------------------------------

#[test]
fn two_lists_at_one_position_is_equivocation() {
    // E1. The direct analogue of a payer reusing a `seq`.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let shadow = signed_cp(&issuer, 0, other.epoch, other.body_digest(), GENESIS_PREV);

    let proof = detect_equivocation(&chain[0], &shadow).expect("equivocation");
    assert_eq!(proof.kind(), Some(EquivocationKind::DuplicatePosition));
    assert_eq!(
        verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).unwrap(),
        EquivocationKind::DuplicatePosition
    );
}

#[test]
fn two_lists_at_one_epoch_at_different_positions_is_equivocation() {
    // E3. The careful version of the same attack: the issuer gives the second list its own
    // log position, so E1 does not fire. Epochs must advance with position, so the pair
    // still cannot both be in one honest log.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let sneaky = append(&issuer, &chain[0], &other);

    let proof = detect_equivocation(&chain[0], &sneaky).expect("equivocation");
    assert_eq!(proof.kind(), Some(EquivocationKind::EpochNotAdvancing));
    verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).expect("verifies");
}

#[test]
fn a_rewritten_history_is_equivocation() {
    // E2. The issuer goes back and re-signs position 1 with a different list, then carries
    // on. A device that kept the original position 1 and is later handed the rewritten
    // position 2 sees a successor naming a predecessor it does not have.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 2);
    let rewritten_1 = signed_cp(
        &issuer,
        1,
        chain[1].epoch,
        list_at(&issuer, chain[1].epoch, &[4242]).body_digest(),
        chain[0].body_digest(),
    );
    let after_rewrite = append(&issuer, &rewritten_1, &list_at(&issuer, 9, &[7]));

    let proof = detect_equivocation(&chain[1], &after_rewrite).expect("equivocation");
    assert_eq!(proof.kind(), Some(EquivocationKind::BrokenLink));
    verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).expect("verifies");
}

#[test]
fn an_epoch_rollback_is_equivocation() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 4);
    // Position 4, correctly linked, but with an epoch from the past.
    let rolled_back = append(&issuer, &chain[3], &list_at(&issuer, 2, &[7]));
    let proof = detect_equivocation(&chain[3], &rolled_back).expect("equivocation");
    assert_eq!(proof.kind(), Some(EquivocationKind::EpochNotAdvancing));
}

#[test]
fn an_honest_chain_never_yields_a_proof() {
    // Every pair, in both orders, including a checkpoint against itself.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 8);
    for a in &chain {
        for b in &chain {
            assert!(
                detect_equivocation(a, b).is_none(),
                "honest pair ({}, {}) reported as equivocation",
                a.seq,
                b.seq
            );
        }
    }
}

#[test]
fn distant_positions_alone_are_not_evidence() {
    // Two entries with a gap between them and advancing epochs are exactly what an honest
    // log looks like to a device that was offline. Detecting a rewrite *inside* the gap
    // needs the intervening links — the documented limit of a bounded window.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 12);
    assert!(detect_equivocation(&chain[0], &chain[11]).is_none());
}

#[test]
fn a_proof_is_canonically_ordered_whichever_way_it_is_found() {
    // Two devices that discover the same equivocation produce the same bytes, so the
    // issuer is reported once, not once per finder.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let shadow = signed_cp(&issuer, 0, other.epoch, other.body_digest(), GENESIS_PREV);

    let forward = detect_equivocation(&chain[0], &shadow).expect("proof");
    let backward = detect_equivocation(&shadow, &chain[0]).expect("proof");
    assert_eq!(forward.encode(), backward.encode());
}

#[test]
fn a_proof_survives_the_wire_in_either_order() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 1);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let shadow = signed_cp(&issuer, 0, other.epoch, other.body_digest(), GENESIS_PREV);
    let proof = detect_equivocation(&chain[0], &shadow).expect("proof");

    let back = EquivocationProof::from_bytes(&proof.encode()).expect("decodes");
    assert_eq!(back, proof);
    verify_equivocation_proof(&back, &issuer.public_key(), &P256Verifier).expect("verifies");

    // Swapped by hand: the ordering is a dedupe convenience, not a security rule, so
    // evidence must not be thrown away over it.
    let swapped = EquivocationProof {
        a: proof.b.clone(),
        b: proof.a.clone(),
    };
    let round_tripped = EquivocationProof::from_bytes(&swapped.encode()).expect("decodes");
    verify_equivocation_proof(&round_tripped, &issuer.public_key(), &P256Verifier)
        .expect("verifies");
}

#[test]
fn a_fabricated_proof_convicts_nobody() {
    // Someone who wants the issuer blamed builds two conflicting checkpoints themselves.
    // They are structurally an equivocation, and worthless: the signatures are not the
    // issuer's.
    let issuer = TestSigner::from_seed(1);
    let liar = TestSigner::from_seed(3);
    let a = signed_cp(&liar, 0, 1, [1u8; 32], GENESIS_PREV);
    let b = signed_cp(&liar, 0, 1, [2u8; 32], GENESIS_PREV);
    let proof = detect_equivocation(&a, &b).expect("structurally a conflict");
    assert_eq!(
        verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
}

#[test]
fn a_proof_of_nothing_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 2);
    let honest_pair = EquivocationProof {
        a: chain[0].clone(),
        b: chain[1].clone(),
    };
    assert_eq!(
        verify_equivocation_proof(&honest_pair, &issuer.public_key(), &P256Verifier).unwrap_err(),
        CheckpointError::NotEquivocation
    );
}

// ---------------------------------------------------------------------------
// Device side: the tracker
// ---------------------------------------------------------------------------

fn tracker(issuer: &TestSigner, retain: usize) -> CheckpointTracker {
    CheckpointTracker::new(issuer.public_key(), retain)
}

#[test]
fn the_first_checkpoint_proves_nothing_and_is_kept() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut t = tracker(&issuer, 8);
    assert_eq!(
        t.offer(&chain[0], &P256Verifier).unwrap(),
        CheckpointVerdict::FirstSeen
    );
    assert_eq!(t.head(), Some(&chain[0]));
}

#[test]
fn a_linked_successor_advances_the_head() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 4);
    let mut t = tracker(&issuer, 8);
    for (i, cp) in chain.iter().enumerate() {
        let expected = if i == 0 {
            CheckpointVerdict::FirstSeen
        } else {
            CheckpointVerdict::Advanced
        };
        assert_eq!(t.offer(cp, &P256Verifier).unwrap(), expected);
    }
    assert_eq!(t.head().map(|c| c.seq), Some(3));
    assert_eq!(t.len(), 4);
}

#[test]
fn a_re_delivery_is_a_duplicate_not_an_event() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 2);
    let mut t = tracker(&issuer, 8);
    t.offer(&chain[0], &P256Verifier).unwrap();
    t.offer(&chain[1], &P256Verifier).unwrap();
    assert_eq!(
        t.offer(&chain[1], &P256Verifier).unwrap(),
        CheckpointVerdict::Duplicate
    );
    assert_eq!(t.len(), 2);
}

#[test]
fn a_device_that_was_offline_installs_across_a_gap() {
    // Block lists are whole snapshots, so a device that missed 9 publications must be able
    // to take the newest one. Refusing would leave it on an older list that blocks fewer
    // cheaters — failing open on revocation, which this protocol never does.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 11);
    let mut t = tracker(&issuer, 8);
    t.offer(&chain[0], &P256Verifier).unwrap();
    assert_eq!(
        t.offer(&chain[10], &P256Verifier).unwrap(),
        CheckpointVerdict::AdvancedWithGap { skipped: 9 }
    );
    assert_eq!(t.head().map(|c| c.seq), Some(10));

    // And the gap can be closed later, link by link, once the missing entries are carried
    // in — nothing about installing across it forfeits the check.
    for w in chain.windows(2) {
        verify_chain_link(&w[0], &w[1], &issuer.public_key(), &P256Verifier).expect("links");
    }
}

#[test]
fn a_second_story_at_the_head_produces_a_usable_proof() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 2);
    let mut t = tracker(&issuer, 8);
    t.offer(&chain[0], &P256Verifier).unwrap();
    t.offer(&chain[1], &P256Verifier).unwrap();

    // The issuer's other story: a different epoch-2 list at position 1.
    let other = list_at(&issuer, lists[1].epoch, &[4242]);
    let shadow = append(&issuer, &chain[0], &other);

    let verdict = t.offer(&shadow, &P256Verifier).unwrap();
    let proof = match verdict {
        CheckpointVerdict::Equivocation(p) => p,
        other => panic!("expected equivocation, got {other:?}"),
    };
    assert_eq!(
        verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).unwrap(),
        EquivocationKind::DuplicatePosition
    );

    // The device keeps the story it already had: adopting the second one would destroy
    // the evidence for the first, which is exactly what the equivocating issuer wants.
    assert_eq!(t.head(), Some(&chain[1]));
    assert_eq!(t.len(), 2);
    assert_eq!(t.at(1), Some(&chain[1]));
}

#[test]
fn a_broken_link_at_the_head_is_evidence_not_merely_a_refusal() {
    // This is why the equivocation pass runs before the continuity check. A successor that
    // does not name the head is not just unusable — it is proof, and a device that only
    // said "rejected" would throw that away.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 1);
    let mut t = tracker(&issuer, 8);
    t.offer(&chain[0], &P256Verifier).unwrap();

    let unlinked = signed_cp(
        &issuer,
        1,
        2,
        list_at(&issuer, 2, &[7]).body_digest(),
        [8u8; 32],
    );
    match t.offer(&unlinked, &P256Verifier).unwrap() {
        CheckpointVerdict::Equivocation(p) => {
            assert_eq!(p.kind(), Some(EquivocationKind::BrokenLink));
            verify_equivocation_proof(&p, &issuer.public_key(), &P256Verifier).expect("verifies");
        }
        other => panic!("expected equivocation, got {other:?}"),
    }
}

#[test]
fn an_older_checkpoint_does_not_move_the_head() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 3);
    let mut t = tracker(&issuer, 8);
    t.offer(&chain[2], &P256Verifier).unwrap();
    assert_eq!(
        t.offer(&chain[0], &P256Verifier).unwrap(),
        CheckpointVerdict::Superseded {
            head: 2,
            offered: 0
        }
    );
    assert_eq!(t.head().map(|c| c.seq), Some(2));
    // Retained anyway: an older entry is extra comparison surface against a later rewrite.
    assert_eq!(t.at(0), Some(&chain[0]));
}

#[test]
fn the_window_is_bounded_and_evicts_the_oldest() {
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 10);
    let mut t = tracker(&issuer, 4);
    for cp in &chain {
        t.offer(cp, &P256Verifier).unwrap();
    }
    assert_eq!(t.len(), 4);
    assert_eq!(t.head().map(|c| c.seq), Some(9));
    assert!(t.at(5).is_none(), "position 5 should have been evicted");
    assert!(t.at(6).is_some());

    // Retaining zero would silently disable every comparison, so it is clamped.
    let mut degenerate = tracker(&issuer, 0);
    degenerate.offer(&chain[0], &P256Verifier).unwrap();
    assert_eq!(degenerate.len(), 1);
}

#[test]
fn a_rewrite_below_the_window_goes_undetected_by_the_phone() {
    // The honest statement of the limit, asserted so it cannot rot into a surprise: once
    // position 0 has been evicted, a device cannot contradict a re-signed position 0. That
    // is what the external anchor is for, not the phone.
    let issuer = TestSigner::from_seed(1);
    let (_, chain) = honest_chain(&issuer, 6);
    let mut t = tracker(&issuer, 2);
    for cp in &chain {
        t.offer(cp, &P256Verifier).unwrap();
    }
    assert!(t.at(0).is_none());

    let rewritten_0 = signed_cp(
        &issuer,
        0,
        1,
        list_at(&issuer, 1, &[4242]).body_digest(),
        GENESIS_PREV,
    );
    assert!(matches!(
        t.offer(&rewritten_0, &P256Verifier).unwrap(),
        CheckpointVerdict::Superseded { .. }
    ));
}

#[test]
fn the_tracker_refuses_a_rival_issuers_checkpoint() {
    let issuer = TestSigner::from_seed(1);
    let rival = TestSigner::from_seed(2);
    let (_, theirs) = honest_chain(&rival, 1);
    let mut t = tracker(&issuer, 8);
    assert_eq!(
        t.offer(&theirs[0], &P256Verifier).unwrap_err(),
        CheckpointError::BadIssuerSignature
    );
    assert!(t.is_empty());
}

#[test]
fn a_held_history_recognises_the_list_it_committed_to() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 3);
    let mut t = tracker(&issuer, 8);
    for cp in &chain {
        t.offer(cp, &P256Verifier).unwrap();
    }
    for list in &lists {
        assert!(t.commits_to(list));
    }
    // A list the issuer never checkpointed to this device is not in its history, even
    // though it is perfectly signed.
    assert!(!t.commits_to(&list_at(&issuer, 2, &[4242])));
}

// ---------------------------------------------------------------------------
// The stateless classifier the FFI exposes
// ---------------------------------------------------------------------------

#[test]
fn classification_matches_the_tracker_with_no_state_of_its_own() {
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 3);

    assert_eq!(
        classify_checkpoint(&[], &chain[0]),
        CheckpointVerdict::FirstSeen
    );
    assert_eq!(
        classify_checkpoint(&refs(&chain[..2]), &chain[2]),
        CheckpointVerdict::Advanced
    );
    assert_eq!(
        classify_checkpoint(&refs(&chain), &chain[1]),
        CheckpointVerdict::Duplicate
    );

    let other = list_at(&issuer, lists[2].epoch, &[4242]);
    let shadow = append(&issuer, &chain[1], &other);
    assert!(matches!(
        classify_checkpoint(&refs(&chain), &shadow),
        CheckpointVerdict::Equivocation(_)
    ));
}

#[test]
fn evidence_wins_over_every_other_verdict() {
    // A checkpoint can look like an ordinary duplicate-position update AND be proof. The
    // order of the checks decides whether the device files it away or reports it, so the
    // precedence is asserted rather than assumed.
    let issuer = TestSigner::from_seed(1);
    let (lists, chain) = honest_chain(&issuer, 3);
    let other = list_at(&issuer, lists[0].epoch, &[4242]);
    let shadow = signed_cp(&issuer, 0, other.epoch, other.body_digest(), GENESIS_PREV);
    assert!(matches!(
        classify_checkpoint(&refs(&chain), &shadow),
        CheckpointVerdict::Equivocation(_)
    ));
}
