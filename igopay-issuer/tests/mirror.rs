//! The public mirror format (B7).
//!
//! A container format, so the tests are mostly about refusing files that a human or a broken
//! job could produce: a dropped line, a hand-edited entry, a head that names a history other
//! than the one in the file. The cryptography is not this module's job — `CheckpointLog`
//! re-verifies everything — but the parser must not let a malformed mirror reach it looking
//! healthy.
//!
//! The one property worth stating out loud: **an append is one added line.** That is what
//! lets somebody who understands none of this read the repository's history and see whether
//! it grew or was rewritten.

mod common;

use common::TestSigner;
use igopay_core::crypto::Signer;
use igopay_core::witness::{Cosignature, WitnessLog};
use igopay_core::P256Verifier;
use igopay_issuer::anchor::AnchorSink;
use igopay_issuer::mirror::{
    check_head, coverage, from_hex, parse_checkpoints, parse_cosignatures, parse_head, parse_key,
    parse_keys, render_checkpoints, render_cosignatures, render_head, render_key, render_witnesses,
    to_hex, MirrorError,
};
use igopay_issuer::{
    publish_with_checkpoint, CheckpointLog, PromiseRegistry, PublishParams, WitnessAnchor,
};

fn params(epoch: u64) -> PublishParams {
    PublishParams::new(epoch, 1_000_000 + epoch)
}

/// A log with `n` publications.
fn log_with(issuer: &TestSigner, n: u64) -> CheckpointLog {
    let reg = PromiseRegistry::new(issuer.public_key());
    let mut log = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=n {
        publish_with_checkpoint(&reg, &params(epoch), issuer, &mut log).expect("publishes");
    }
    log
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

#[test]
fn hex_round_trips_and_is_emitted_lowercase() {
    let bytes: Vec<u8> = (0u8..=255).collect();
    let hex = to_hex(&bytes);
    assert_eq!(hex, hex.to_lowercase());
    assert_eq!(from_hex(&hex).unwrap(), bytes);
    // Liberal on input: an uppercase or padded line still decodes.
    assert_eq!(
        from_hex(" DEADBEEF \n").unwrap(),
        vec![0xde, 0xad, 0xbe, 0xef]
    );
    // And refuses what cannot be bytes.
    assert!(from_hex("abc").is_none());
    assert!(from_hex("").is_none());
    assert!(from_hex("zz").is_none());
}

// ---------------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------------

#[test]
fn a_rendered_log_parses_back_and_verifies() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 5);

    let text = render_checkpoints(&log);
    assert_eq!(text.lines().count(), 5);

    let parsed = parse_checkpoints(&text).expect("parses");
    assert_eq!(parsed, log.entries());

    // The auditor's whole job: parse, then let the log re-verify every signature and link.
    let resumed =
        CheckpointLog::resume(issuer.public_key(), parsed, &P256Verifier).expect("verifies");
    assert_eq!(resumed.head(), log.head());

    // And the head file names the last entry.
    let head = parse_head(&render_head(&log)).expect("parses");
    check_head(resumed.entries(), head).expect("head matches");
}

#[test]
fn an_append_is_exactly_one_added_line() {
    // The property the whole format exists for.
    let issuer = TestSigner::from_seed(1);
    let reg = PromiseRegistry::new(issuer.public_key());
    let mut log = CheckpointLog::new(issuer.public_key());
    for epoch in 1..=3 {
        publish_with_checkpoint(&reg, &params(epoch), &issuer, &mut log).unwrap();
    }
    let before = render_checkpoints(&log);

    publish_with_checkpoint(&reg, &params(4), &issuer, &mut log).unwrap();
    let after = render_checkpoints(&log);

    assert!(
        after.starts_with(&before),
        "publishing must not rewrite a line that was already committed"
    );
    assert_eq!(after.lines().count(), before.lines().count() + 1);
}

#[test]
fn an_empty_mirror_is_valid_and_says_nothing() {
    let issuer = TestSigner::from_seed(1);
    let log = CheckpointLog::new(issuer.public_key());
    assert_eq!(render_checkpoints(&log), "");
    assert_eq!(render_head(&log), "");
    assert!(parse_checkpoints("").unwrap().is_empty());
    assert_eq!(parse_head("").unwrap(), None);
    check_head(&[], None).expect("an empty mirror is consistent");
}

#[test]
fn blank_lines_and_comments_are_tolerated() {
    // A stray trailing newline must not be an error, and an operator should be able to leave
    // a note in the file without breaking every reader.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 2);
    let annotated = format!(
        "# igopay checkpoint log\n\n{}\n\n# end\n",
        render_checkpoints(&log).trim()
    );
    assert_eq!(parse_checkpoints(&annotated).unwrap(), log.entries());
}

// ---------------------------------------------------------------------------
// What the parser must refuse
// ---------------------------------------------------------------------------

#[test]
fn a_dropped_line_is_refused_with_its_position() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 4);
    let rendered = render_checkpoints(&log);
    let lines: Vec<&str> = rendered.lines().collect();
    let with_hole = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[3]);

    assert_eq!(
        parse_checkpoints(&with_hole).unwrap_err(),
        MirrorError::OutOfOrder { line: 2, seq: 2 }
    );
}

#[test]
fn a_reordered_log_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 3);
    let rendered = render_checkpoints(&log);
    let lines: Vec<&str> = rendered.lines().collect();
    let swapped = format!("{}\n{}\n{}\n", lines[1], lines[0], lines[2]);
    assert!(matches!(
        parse_checkpoints(&swapped).unwrap_err(),
        MirrorError::OutOfOrder { .. }
    ));
}

#[test]
fn a_hand_edited_line_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 2);
    let text = render_checkpoints(&log);

    // Not hex.
    let not_hex = text.replacen('a', "z", 1);
    assert!(matches!(
        parse_checkpoints(&not_hex),
        Err(MirrorError::BadHex { .. }) | Err(MirrorError::BadArtefact { .. })
    ));

    // Hex, but truncated so it is no longer a canonical checkpoint.
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let shorter = lines[1].len() - 4;
    lines[1].truncate(shorter);
    let truncated = lines.join("\n");
    assert!(matches!(
        parse_checkpoints(&truncated),
        Err(MirrorError::BadArtefact { .. }) | Err(MirrorError::BadHex { .. })
    ));
}

#[test]
fn a_head_that_names_another_history_is_refused() {
    // The head file is what gets timestamped externally, so if it named anything other than
    // the log's last entry the timestamp would pin a history nobody published.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 3);
    let entries = log.entries().to_vec();

    check_head(&entries, parse_head(&render_head(&log)).unwrap()).expect("consistent");

    // An earlier entry's digest, i.e. a head file that was not updated.
    let stale = Some(entries[0].body_digest());
    assert!(matches!(
        check_head(&entries, stale),
        Err(MirrorError::HeadMismatch { .. })
    ));
    // A missing head file for a non-empty log.
    assert!(matches!(
        check_head(&entries, None),
        Err(MirrorError::HeadMismatch { .. })
    ));
    // A head for an empty log.
    assert!(matches!(
        check_head(&[], stale),
        Err(MirrorError::HeadMismatch { .. })
    ));
}

#[test]
fn a_tampered_line_survives_parsing_and_dies_at_verification() {
    // The division of labour, asserted: the container format does no cryptography, so a line
    // that is still a well-formed checkpoint parses fine and is caught by `resume`. A parser
    // that verified signatures would tempt a caller into thinking parsing was enough.
    let issuer = TestSigner::from_seed(1);
    let log = log_with(&issuer, 3);
    let mut entries = log.entries().to_vec();
    entries[1].epoch += 1; // still canonical, no longer signed

    let text = render_checkpoints(
        &CheckpointLog::resume(issuer.public_key(), log.entries().to_vec(), &P256Verifier).unwrap(),
    );
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    lines[1] = to_hex(&entries[1].encode());
    let tampered = lines.join("\n");

    let parsed = parse_checkpoints(&tampered).expect("a well-formed line still parses");
    assert!(CheckpointLog::resume(issuer.public_key(), parsed, &P256Verifier).is_err());
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

#[test]
fn keys_round_trip_and_are_canonically_ordered() {
    let issuer = TestSigner::from_seed(1);
    assert_eq!(
        parse_key(&render_key(&issuer.public_key())),
        Some(issuer.public_key())
    );

    let a = TestSigner::from_seed(2).public_key();
    let b = TestSigner::from_seed(3).public_key();
    // Whichever order they are given in, the file has one appearance.
    assert_eq!(render_witnesses(&[a, b]), render_witnesses(&[b, a]));
    assert_eq!(parse_keys(&render_witnesses(&[a, b])).unwrap().len(), 2);

    // An empty witness file is an honest statement, not an error.
    assert!(parse_keys("").unwrap().is_empty());
    // A truncated key is refused rather than padded.
    assert!(matches!(
        parse_keys("deadbeef\n"),
        Err(MirrorError::BadKey { .. })
    ));
}

// ---------------------------------------------------------------------------
// Cosignatures and coverage
// ---------------------------------------------------------------------------

/// Cosign `seq` of `log` as `witness`.
fn cosign_at(
    issuer: &TestSigner,
    witness: &TestSigner,
    log: &CheckpointLog,
    seq: u64,
) -> Cosignature {
    let mut wl = WitnessLog::new(witness.public_key(), issuer.public_key());
    wl.cosign(
        log.at(seq).unwrap(),
        1_500_000 + seq,
        witness,
        &P256Verifier,
    )
    .expect("cosigns")
}

#[test]
fn cosignatures_round_trip_and_append_without_rewriting() {
    // Attestations arrive after publication, sometimes much later. Storing them inline would
    // mean editing a committed line; in their own file a late reply is a new line.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let log = log_with(&issuer, 3);

    let first = vec![cosign_at(&issuer, &witness, &log, 0)];
    let before = render_cosignatures(&first);

    let mut both = first.clone();
    both.push(cosign_at(&issuer, &witness, &log, 2));
    let after = render_cosignatures(&both);

    assert!(after.starts_with(&before));
    assert_eq!(after.lines().count(), 2);
    assert_eq!(parse_cosignatures(&after).unwrap(), both);
}

#[test]
fn coverage_is_computable_from_the_mirror_alone() {
    // What a reader who clones the repository can conclude without asking anybody: which
    // positions a trusted witness attested to.
    let issuer = TestSigner::from_seed(1);
    let w1 = TestSigner::from_seed(2);
    let w2 = TestSigner::from_seed(3);
    let log = log_with(&issuer, 4);

    let cosigs = vec![
        cosign_at(&issuer, &w1, &log, 0),
        cosign_at(&issuer, &w1, &log, 1),
        cosign_at(&issuer, &w2, &log, 1),
    ];
    let text = render_cosignatures(&cosigs);

    let entries = parse_checkpoints(&render_checkpoints(&log)).unwrap();
    let parsed = parse_cosignatures(&text).unwrap();
    let trusted = parse_keys(&render_witnesses(&[w1.public_key(), w2.public_key()])).unwrap();

    let (per_position, unknown) = coverage(
        &entries,
        &parsed,
        &issuer.public_key(),
        &trusted,
        &P256Verifier,
    );
    assert_eq!(unknown, 0);
    assert_eq!(per_position.len(), 4);
    assert_eq!(per_position[0].witnesses, 1);
    assert_eq!(per_position[1].witnesses, 2);
    assert_eq!(per_position[2].witnesses, 0);
    assert_eq!(per_position[3].witnesses, 0);
    assert_eq!(per_position[1].epoch, 2);
}

#[test]
fn coverage_ignores_what_it_cannot_credit() {
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let stranger = TestSigner::from_seed(4);
    let log = log_with(&issuer, 2);
    let trusted = [witness.public_key()];

    let mut cosigs = vec![
        // A stranger's attestation: valid, and not ours to count.
        cosign_at(&issuer, &stranger, &log, 0),
        // A repeat from the same witness, which must not count twice.
        cosign_at(&issuer, &witness, &log, 0),
        cosign_at(&issuer, &witness, &log, 0),
    ];
    // A trusted witness's cosignature that does not verify.
    let mut tampered = cosign_at(&issuer, &witness, &log, 1);
    tampered.sig_witness[5] ^= 0xff;
    cosigs.push(tampered);
    // An attestation for a checkpoint that is not in this log.
    let other_log = log_with(&TestSigner::from_seed(9), 1);
    cosigs.push(cosign_at(
        &TestSigner::from_seed(9),
        &witness,
        &other_log,
        0,
    ));

    let entries = log.entries().to_vec();
    let (per_position, unknown) = coverage(
        &entries,
        &cosigs,
        &issuer.public_key(),
        &trusted,
        &P256Verifier,
    );
    assert_eq!(per_position[0].witnesses, 1, "one witness, counted once");
    assert_eq!(
        per_position[1].witnesses, 0,
        "a bad signature credits nothing"
    );
    assert_eq!(unknown, 3);
}

#[test]
fn the_collected_artefact_and_the_mirror_agree() {
    // The two halves of the anchor seam meet here: what `WitnessAnchor` collected is what the
    // mirror publishes, and a reader recomputes the same coverage from the text.
    let issuer = TestSigner::from_seed(1);
    let witness = TestSigner::from_seed(2);
    let log = log_with(&issuer, 1);
    let head = log.head().unwrap();

    let mut sink = WitnessAnchor::new(issuer.public_key(), vec![witness.public_key()], 1);
    sink.submit(head);
    let cosig = cosign_at(&issuer, &witness, &log, 0);
    assert!(sink.record_cosignature(cosig.clone(), &P256Verifier));

    let artefact = sink.witnessed(&head.body_digest()).expect("collected");
    let published = render_cosignatures(&artefact.cosignatures);
    assert_eq!(parse_cosignatures(&published).unwrap(), vec![cosig]);

    let (per_position, unknown) = coverage(
        log.entries(),
        &parse_cosignatures(&published).unwrap(),
        &issuer.public_key(),
        &[witness.public_key()],
        &P256Verifier,
    );
    assert_eq!(per_position[0].witnesses, 1);
    assert_eq!(unknown, 0);
}
