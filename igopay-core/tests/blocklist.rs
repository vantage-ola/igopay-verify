//! Block-list publication and install (B13).
//!
//! The filter itself is easy; what these tests are actually about is everything a
//! device must refuse. A block list is an instruction to reject someone's money, so a
//! forged, replayed, or malformed one is an attack on an honest payer — either
//! censoring them or crashing the wallet that would have accepted them.

mod common;

use common::TestSigner;
use igopay_core::crypto::{PubKeyBytes, Signer};
use igopay_core::{
    hashes_for_bits_per_item, BlockList, BlockListError, P256Verifier, SignedBlockList,
    MAX_EXACT_RECENT, MAX_FILTER_BYTES, MAX_HASHES,
};

/// Synthesize a distinct 33-byte key. The filter hashes raw bytes and never parses a
/// curve point, so these are adequate for filter statistics and far cheaper than
/// generating thousands of real P-256 keys.
fn key(n: u32) -> PubKeyBytes {
    let mut k = [0u8; 33];
    k[0] = 0x02;
    k[1..5].copy_from_slice(&n.to_be_bytes());
    k
}

fn sign(doc: &mut SignedBlockList, issuer: &TestSigner) {
    doc.sig_issuer = issuer.sign_prehash(&doc.body_digest());
}

fn published(list: &BlockList, issuer: &TestSigner, epoch: u64) -> SignedBlockList {
    let mut doc = list.to_unsigned(epoch, 1_000_000, 1_086_400);
    sign(&mut doc, issuer);
    doc
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

#[test]
fn round_trip_preserves_every_field() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(3, 12);
    for n in 0..3 {
        list.insert(&key(n));
        list.insert_recent(key(n));
    }
    let doc = published(&list, &issuer, 7);

    let bytes = doc.encode();
    let back = SignedBlockList::decode(&bytes).expect("decodes");
    assert_eq!(back, doc);
}

#[test]
fn encoding_is_deterministic() {
    let issuer = TestSigner::from_seed(1);
    let mut a = BlockList::sized_for(4, 12);
    let mut b = BlockList::sized_for(4, 12);
    // Insert in opposite orders: the exact set is a BTreeSet, so the wire order is
    // canonical regardless of insertion order.
    for n in 0..4 {
        a.insert(&key(n));
        a.insert_recent(key(n));
    }
    for n in (0..4).rev() {
        b.insert(&key(n));
        b.insert_recent(key(n));
    }
    assert_eq!(
        published(&a, &issuer, 1).encode(),
        published(&b, &issuer, 1).encode()
    );
}

#[test]
fn decode_rejects_trailing_bytes() {
    let issuer = TestSigner::from_seed(1);
    let doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    let mut bytes = doc.encode();
    bytes.push(0x00);
    assert!(matches!(
        SignedBlockList::decode(&bytes),
        Err(BlockListError::Decode(_))
    ));
}

// ---------------------------------------------------------------------------
// Install: what it accepts
// ---------------------------------------------------------------------------

#[test]
fn a_blocked_payer_is_found_after_install() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(2, 12);
    list.insert(&key(42));
    let doc = published(&list, &issuer, 1);

    let installed = doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .expect("installs");
    assert!(installed.contains(&key(42)));
    assert_eq!(installed.epoch(), 1);
}

#[test]
fn an_empty_list_blocks_nobody() {
    let issuer = TestSigner::from_seed(1);
    let doc = published(&BlockList::sized_for(0, 12), &issuer, 1);
    let installed = doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .expect("installs");
    for n in 0..500 {
        assert!(!installed.contains(&key(n)), "empty filter matched key {n}");
    }
}

#[test]
fn first_install_accepts_any_epoch() {
    let issuer = TestSigner::from_seed(1);
    let doc = published(&BlockList::sized_for(1, 12), &issuer, 9_999);
    assert!(doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .is_ok());
}

#[test]
fn a_newer_epoch_installs_over_an_older_one() {
    let issuer = TestSigner::from_seed(1);
    let doc = published(&BlockList::sized_for(1, 12), &issuer, 5);
    let installed = doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, Some(4))
        .expect("installs over epoch 4");
    assert_eq!(installed.epoch(), 5);
}

// ---------------------------------------------------------------------------
// Install: what it refuses
// ---------------------------------------------------------------------------

#[test]
fn a_forged_issuer_signature_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let impostor = TestSigner::from_seed(2);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    // A structurally valid low-S signature, just from the wrong key.
    sign(&mut doc, &impostor);

    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::BadIssuerSignature
    );
}

#[test]
fn a_malleable_high_s_signature_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    doc.sig_issuer = TestSigner::malleate(&doc.sig_issuer);

    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::MalleableSignature
    );
}

#[test]
fn tampering_with_the_filter_bits_breaks_the_signature() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(2, 12);
    list.insert(&key(1));
    let mut doc = published(&list, &issuer, 1);

    // Flip one bit: an attacker adding an innocent payer to the filter, or clearing a
    // guilty one. Either way the signature covers the whole body.
    doc.bits[0] ^= 0b1000_0000;
    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::BadIssuerSignature
    );
}

#[test]
fn tampering_with_the_exact_set_breaks_the_signature() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(2, 12);
    list.insert_recent(key(1));
    let mut doc = published(&list, &issuer, 1);

    doc.exact_recent.push(key(2)); // still ascending, so shape is fine
    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::BadIssuerSignature
    );
}

#[test]
fn a_replayed_older_list_is_refused() {
    let issuer = TestSigner::from_seed(1);
    // Epoch 3 was published, the device installed it, then an attacker replays epoch 2
    // to un-block a payer caught since.
    let old = published(&BlockList::sized_for(1, 12), &issuer, 2);
    assert_eq!(
        old.verify_and_open(&issuer.public_key(), &P256Verifier, Some(3))
            .unwrap_err(),
        BlockListError::StaleEpoch {
            current: 3,
            offered: 2
        }
    );
}

#[test]
fn an_equal_epoch_is_refused() {
    // Strictly greater, not greater-or-equal: two different lists at the same epoch
    // would otherwise let an attacker swap a device onto whichever one omits the payer
    // they care about.
    let issuer = TestSigner::from_seed(1);
    let doc = published(&BlockList::sized_for(1, 12), &issuer, 3);
    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, Some(3))
            .unwrap_err(),
        BlockListError::StaleEpoch {
            current: 3,
            offered: 3
        }
    );
}

#[test]
fn an_inverted_validity_window_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = BlockList::sized_for(1, 12).to_unsigned(1, 2_000, 1_000);
    sign(&mut doc, &issuer);
    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::InvertedWindow
    );
}

// ---------------------------------------------------------------------------
// Expiry must not fail open
// ---------------------------------------------------------------------------

#[test]
fn an_expired_list_still_installs_and_still_blocks() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(2, 12);
    list.insert(&key(7));
    list.insert_recent(key(7));
    // Window closed long before "now".
    let mut doc = list.to_unsigned(1, 1_000, 2_000);
    sign(&mut doc, &issuer);

    let installed = doc
        .verify_and_open(&issuer.public_key(), &P256Verifier, None)
        .expect("an expired list must still install");

    // Refusing it would leave the device on an older list that blocks fewer cheaters,
    // and waiting for expiry would become a way to get un-blocked.
    assert!(installed.contains(&key(7)));
    assert!(installed.contains_exact(&key(7)));
    assert!(installed.is_stale(9_999));
    assert!(!installed.is_stale(1_500));
}

// ---------------------------------------------------------------------------
// Malformed lists must not panic a phone
// ---------------------------------------------------------------------------

#[test]
fn zero_num_bits_is_refused_rather_than_dividing_by_zero() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    doc.num_bits = 0;
    doc.bits.clear();
    sign(&mut doc, &issuer); // correctly signed, so only the shape check can catch it

    assert_eq!(
        doc.verify_and_open(&issuer.public_key(), &P256Verifier, None)
            .unwrap_err(),
        BlockListError::BadGeometry
    );
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::BadGeometry
    );
}

#[test]
fn zero_hash_probes_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    doc.num_hashes = 0;
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::BadGeometry
    );
}

#[test]
fn a_short_bit_buffer_is_refused_rather_than_indexing_out_of_bounds() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(64, 12), &issuer, 1);
    doc.bits.truncate(4); // claims 768 bits, carries 32
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::BadGeometry
    );
}

#[test]
fn an_oversized_filter_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    doc.num_bits = (MAX_FILTER_BYTES as u64) * 8 + 8;
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::TooLarge
    );
}

#[test]
fn too_many_hash_probes_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut doc = published(&BlockList::sized_for(1, 12), &issuer, 1);
    doc.num_hashes = MAX_HASHES as u64 + 1;
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::TooLarge
    );
}

#[test]
fn too_many_exact_entries_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(MAX_EXACT_RECENT + 1, 12);
    for n in 0..=(MAX_EXACT_RECENT as u32) {
        list.insert_recent(key(n));
    }
    let doc = published(&list, &issuer, 1);
    assert_eq!(doc.exact_recent.len(), MAX_EXACT_RECENT + 1);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::TooLarge
    );
}

#[test]
fn an_unsorted_exact_set_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(3, 12);
    for n in 0..3 {
        list.insert_recent(key(n));
    }
    let mut doc = published(&list, &issuer, 1);
    doc.exact_recent.swap(0, 2); // descending
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::ExactSetNotSorted
    );
}

#[test]
fn a_duplicated_exact_entry_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(2, 12);
    list.insert_recent(key(1));
    let mut doc = published(&list, &issuer, 1);
    doc.exact_recent.push(key(1)); // equal, so not strictly ascending
    sign(&mut doc, &issuer);
    assert_eq!(
        SignedBlockList::decode(&doc.encode()).unwrap_err(),
        BlockListError::ExactSetNotSorted
    );
}

// ---------------------------------------------------------------------------
// Filter behaviour
// ---------------------------------------------------------------------------

#[test]
fn the_exact_set_never_false_positives() {
    let mut list = BlockList::sized_for(8, 12);
    for n in 0..8 {
        list.insert_recent(key(n));
    }
    for n in 0..8 {
        assert!(list.contains_exact(&key(n)));
    }
    for n in 8..2_000 {
        assert!(!list.contains_exact(&key(n)), "exact set matched key {n}");
    }
}

#[test]
fn every_inserted_payer_is_always_found() {
    // The one-directional guarantee: no false negatives, ever.
    let mut list = BlockList::sized_for(1_000, 12);
    for n in 0..1_000 {
        list.insert(&key(n));
    }
    for n in 0..1_000 {
        assert!(list.contains(&key(n)), "false negative for key {n}");
    }
}

#[test]
fn false_positive_rate_stays_within_budget() {
    // 12 bits per item with 8 probes is nominally ~0.3%. Assert well under 1% so the
    // test is stable but would still catch a broken hash-position derivation.
    const BLOCKED: u32 = 1_000;
    const TRIALS: u32 = 20_000;
    let mut list = BlockList::sized_for(BLOCKED as usize, 12);
    for n in 0..BLOCKED {
        list.insert(&key(n));
    }
    let fps = (BLOCKED..BLOCKED + TRIALS)
        .filter(|n| list.contains(&key(*n)))
        .count();
    let rate = fps as f64 / TRIALS as f64;
    assert!(rate < 0.01, "false-positive rate {rate} exceeded 1%");
}

#[test]
fn probe_count_is_integer_deterministic() {
    // Floating point here would make the filter geometry platform-dependent, and the
    // geometry is part of the wire format.
    assert_eq!(hashes_for_bits_per_item(0), 1);
    assert_eq!(hashes_for_bits_per_item(1), 1);
    assert_eq!(hashes_for_bits_per_item(8), 5);
    assert_eq!(hashes_for_bits_per_item(10), 6);
    assert_eq!(hashes_for_bits_per_item(12), 8);
    assert_eq!(hashes_for_bits_per_item(16), 11);
    assert_eq!(hashes_for_bits_per_item(1_000), MAX_HASHES);
}

#[test]
fn sizing_matches_the_requested_budget() {
    let list = BlockList::sized_for(100, 12);
    assert_eq!(list.num_bits(), 1_200);
    assert_eq!(list.num_hashes(), 8);
    assert_eq!(list.bits().len(), 150);

    // Degenerate inputs still produce a usable filter rather than panicking.
    let tiny = BlockList::sized_for(0, 0);
    assert!(tiny.num_bits() >= 8);
    assert!(tiny.num_hashes() >= 1);
}

#[test]
fn published_size_stays_distributable() {
    // The distribution budget, measured rather than assumed. A block list has to reach
    // devices that are rarely online, so its growth curve decides whether B13 is
    // practical at all — and it grows with the number of *cheaters*, not the number of
    // users.
    //
    // At 12 bits per payer plus a 256-entry exact set, measured wire sizes are:
    //     1,000 blocked →  ~10.5 KB
    //    10,000 blocked →   ~24 KB
    //   100,000 blocked →  ~159 KB
    //
    // Note which term dominates: the exact set costs 34 bytes an entry and is nearly the
    // whole bill at small counts (256 entries ≈ 8.7 KB against a 1.5 KB filter for 1,000
    // payers). Trimming the exact window is the lever if size ever matters.
    let issuer = TestSigner::from_seed(1);
    let mut list = BlockList::sized_for(10_000, 12);
    for n in 0..10_000 {
        list.insert(&key(n));
    }
    for n in 9_744..10_000 {
        list.insert_recent(key(n));
    }
    let size = published(&list, &issuer, 1).encode().len();
    assert!(
        size < 32 * 1024,
        "10k blocked payers published to {size} bytes, over the 32 KB guard"
    );
}
