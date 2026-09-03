//! End-to-end witness loop, driving the real binary.
//!
//! The rule itself — at most one head per position, ever — is proved in
//! `igopay-core/tests/witness.rs`. What only exists here is the part that spans *processes*:
//! that the rule survives the tool exiting, that a refusal comes out of the command as
//! publishable evidence with a distinguishable exit code, and that a released cosignature is
//! never something the witness has forgotten by the next invocation.
//!
//! Every checkpoint below is synthesised directly rather than published by an issuer. That is
//! not a shortcut: a witness never looks at a block list, only at the issuer's signature over
//! a position, so the list digests here are arbitrary on purpose.

use std::path::Path;
use std::process::{Command, Output};

use igopay_core::checkpoint::{Checkpoint, EquivocationProof};
use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::witness::{Cosignature, WitnessedCheckpoint};
use igopay_core::{
    from_hex, to_hex, verify_equivocation_proof, verify_witnessed, P256Verifier, GENESIS_PREV,
};

const BIN: &str = env!("CARGO_BIN_EXE_igopay-witness");

/// A deterministic P-256 signer, so the artefacts in these tests are reproducible.
struct Seeded {
    sk: p256::ecdsa::SigningKey,
}

impl Seeded {
    fn new(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        Seeded {
            sk: p256::ecdsa::SigningKey::from_bytes(&bytes.into()).expect("valid scalar"),
        }
    }
}

impl Signer for Seeded {
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).expect("sign");
        sig.normalize_s().unwrap_or(sig).to_bytes().into()
    }

    fn public_key(&self) -> PubKeyBytes {
        self.sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("33-byte key")
    }
}

fn checkpoint(issuer: &Seeded, seq: u64, epoch: u64, list_tag: u8, prev: [u8; 32]) -> Checkpoint {
    let mut cp = Checkpoint {
        seq,
        epoch,
        list_digest: [list_tag; 32],
        prev_hash: prev,
        issued_at: 1_700_000_000 + seq,
        sig_issuer: [0u8; 64],
    };
    cp.sig_issuer = issuer.sign_prehash(&cp.body_digest());
    cp
}

/// An honest chain of `n` publications: consecutive positions, advancing epochs, linked.
fn chain(issuer: &Seeded, n: u64) -> Vec<Checkpoint> {
    let mut out: Vec<Checkpoint> = Vec::new();
    for i in 0..n {
        let prev = out.last().map_or(GENESIS_PREV, |c| c.body_digest());
        out.push(checkpoint(issuer, i, i + 1, i as u8 + 1, prev));
    }
    out
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("igopay-witness-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn s(&self) -> String {
        self.0.display().to_string()
    }

    fn read(&self, name: &str) -> String {
        std::fs::read_to_string(self.0.join(name)).unwrap_or_default()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("runs")
}

fn ok(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected success from {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Run a command expected to exit with `code`, returning `(stdout, stderr)`.
fn exits(code: i32, args: &[&str]) -> (String, String) {
    let out = run(args);
    assert_eq!(
        out.status.code(),
        Some(code),
        "expected exit {code} from {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

/// Set up a witness watching `issuer`, and return its public key.
fn init(d: &Scratch, issuer: &Seeded) -> PubKeyBytes {
    ok(&["init", &d.s(), "--issuer", &to_hex(&issuer.public_key())]);
    let printed = ok(&["pubkey", &d.s()]);
    from_hex(printed.trim())
        .expect("hex")
        .as_slice()
        .try_into()
        .expect("33 bytes")
}

fn cosign(d: &Scratch, cp: &Checkpoint) -> Cosignature {
    let hex = ok(&["cosign", &d.s(), &to_hex(&cp.encode())]);
    Cosignature::from_bytes(&from_hex(hex.trim()).expect("hex")).expect("canonical cosignature")
}

// ---------------------------------------------------------------------------
// The loop
// ---------------------------------------------------------------------------

#[test]
fn a_fresh_witness_cosigns_a_chain_and_the_result_verifies_offline() {
    // The whole point, in one test: what comes out of this tool is something a payee with no
    // network can check, using nothing but the two public keys.
    let d = Scratch::new("loop");
    let issuer = Seeded::new(1);
    let witness_pub = init(&d, &issuer);
    let cps = chain(&issuer, 4);

    for cp in &cps {
        let cosig = cosign(&d, cp);
        assert_eq!(cosig.checkpoint_digest, cp.body_digest());
        assert_eq!(cosig.issuer_pubkey, issuer.public_key());
        assert_eq!(cosig.witness_pubkey, witness_pub);

        let mut wc = WitnessedCheckpoint::new(cp.clone());
        assert!(wc.attach(cosig));
        let coverage = verify_witnessed(&wc, &issuer.public_key(), &[witness_pub], &P256Verifier)
            .expect("a payee verifies it");
        assert!(coverage.is_witnessed());
        assert_eq!(coverage.unknown, 0);
    }

    assert_eq!(d.read("issued.hex").lines().count(), 4);
    assert_eq!(d.read("seen.hex").lines().count(), 4);
    let (_, report) = exits(0, &["verify", &d.s()]);
    assert!(report.contains("4 checkpoint(s) held, 4 cosignature(s) issued"));
}

#[test]
fn asking_twice_gets_the_same_cosignature_back_not_a_second_one() {
    // Across processes, so this exercises persistence rather than an in-memory map. A witness
    // that re-signed would hand two devices different bytes for the same head, and a payee
    // comparing artefacts would see a difference the issuer did not create.
    let d = Scratch::new("idempotent");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let cp = chain(&issuer, 1).remove(0);

    let first = ok(&["cosign", &d.s(), &to_hex(&cp.encode())]);
    let again = ok(&["cosign", &d.s(), &to_hex(&cp.encode())]);
    assert_eq!(first, again, "a re-request must re-state, not re-sign");
    assert_eq!(d.read("issued.hex").lines().count(), 1);
}

#[test]
fn a_second_head_at_a_position_is_refused_across_a_restart_with_a_publishable_proof() {
    // The load-bearing test for this binary. The rule is "ever", and `ever` has to survive the
    // process exiting — the issuer's cheapest attack is to ask again after a reboot.
    let d = Scratch::new("conflict");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let honest = chain(&issuer, 2);
    cosign(&d, &honest[0]);
    cosign(&d, &honest[1]);

    // A different epoch-2 list, re-signed at position 1: the story told to a second device.
    let second_story = checkpoint(&issuer, 1, 2, 99, honest[0].body_digest());
    assert_ne!(second_story.body_digest(), honest[1].body_digest());

    let (stdout, stderr) = exits(3, &["cosign", &d.s(), &to_hex(&second_story.encode())]);
    assert!(stderr.contains("CONFLICT at position 1"));

    // stdout is the evidence, and it stands on its own.
    let proof = EquivocationProof::from_bytes(&from_hex(stdout.trim()).expect("hex"))
        .expect("canonical proof");
    verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier)
        .expect("anyone with the issuer's public key can check it");

    // Nothing was adopted and nothing was signed.
    assert_eq!(d.read("issued.hex").lines().count(), 2);
    assert_eq!(d.read("seen.hex").lines().count(), 2);
    let still = ok(&["cosign", &d.s(), &to_hex(&honest[1].encode())]);
    assert_eq!(
        Cosignature::from_bytes(&from_hex(still.trim()).unwrap())
            .unwrap()
            .checkpoint_digest,
        honest[1].body_digest(),
        "the honest head must survive the attempt"
    );
}

#[test]
fn check_answers_a_payee_who_walks_up_with_a_head() {
    let d = Scratch::new("check");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let cps = chain(&issuer, 3);
    for cp in &cps {
        cosign(&d, cp);
    }

    // Recognised: the cosignature comes back, so the payee can attach it.
    let (stdout, stderr) = exits(0, &["check", &d.s(), &to_hex(&cps[1].encode())]);
    assert!(stderr.contains("Recognised"));
    let cosig = Cosignature::from_bytes(&from_hex(stdout.trim()).expect("hex")).expect("cosig");
    assert_eq!(cosig.checkpoint_digest, cps[1].body_digest());

    // A position nobody ever offered: no opinion, and it says so rather than implying health.
    let unseen = checkpoint(&issuer, 40, 41, 7, [9u8; 32]);
    let (_, stderr) = exits(4, &["check", &d.s(), &to_hex(&unseen.encode())]);
    assert!(stderr.contains("No opinion"));
    assert!(
        stderr.contains("nobody asked"),
        "silence must not read as a clean bill of health"
    );

    // A head that contradicts one it signed: evidence, and a distinct exit code.
    let rival = checkpoint(&issuer, 2, 3, 88, cps[1].body_digest());
    let (stdout, _) = exits(3, &["check", &d.s(), &to_hex(&rival.encode())]);
    let proof =
        EquivocationProof::from_bytes(&from_hex(stdout.trim()).expect("hex")).expect("proof");
    verify_equivocation_proof(&proof, &issuer.public_key(), &P256Verifier).expect("verifies");
    // `check` is read-only.
    assert_eq!(d.read("issued.hex").lines().count(), 3);
}

// ---------------------------------------------------------------------------
// Things a witness must refuse
// ---------------------------------------------------------------------------

#[test]
fn a_checkpoint_from_another_issuer_is_refused_and_nothing_is_written() {
    let d = Scratch::new("stranger");
    let issuer = Seeded::new(1);
    let stranger = Seeded::new(7);
    init(&d, &issuer);

    let theirs = chain(&stranger, 1).remove(0);
    let (_, stderr) = exits(1, &["cosign", &d.s(), &to_hex(&theirs.encode())]);
    assert!(
        stderr.contains("BadIssuerSignature"),
        "stderr was: {stderr}"
    );
    assert_eq!(d.read("issued.hex").lines().count(), 0);
    assert_eq!(d.read("seen.hex").lines().count(), 0);
}

#[test]
fn init_refuses_to_overwrite_a_witness_that_has_already_signed_things() {
    // The worst available accident: a second `init` that silently replaced the key would
    // discard every position this witness had attested to, which is how it gets talked into
    // cosigning a second head at all of them.
    let d = Scratch::new("reinit");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let before = d.read("witness.key");
    cosign(&d, &chain(&issuer, 1).remove(0));

    let (_, stderr) = exits(
        1,
        &["init", &d.s(), "--issuer", &to_hex(&issuer.public_key())],
    );
    assert!(stderr.contains("witness.key"), "stderr was: {stderr}");
    assert_eq!(d.read("witness.key"), before, "the key must be untouched");
    assert_eq!(d.read("issued.hex").lines().count(), 1);
}

#[test]
fn a_tampered_state_file_is_refused_at_load_rather_than_signed_on_top_of() {
    let d = Scratch::new("tampered");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let cps = chain(&issuer, 2);
    for cp in &cps {
        cosign(&d, cp);
    }

    // Well-formed, no longer signed.
    let seen = d.read("seen.hex");
    let mut lines: Vec<String> = seen.lines().map(String::from).collect();
    let last = lines[1].clone();
    lines[1] = format!("{}deadbeef", &last[..last.len() - 8]);
    std::fs::write(d.path().join("seen.hex"), lines.join("\n") + "\n").expect("write");

    for cmd in ["verify", "status", "pubkey"] {
        let (_, stderr) = exits(1, &[cmd, &d.s()]);
        assert!(
            stderr.contains("does not verify"),
            "`{cmd}` must refuse tampered state; stderr was: {stderr}"
        );
    }
}

#[test]
fn a_cosignature_whose_checkpoint_went_missing_is_reported_not_repaired() {
    // A witness holding a signature without the thing it signed cannot produce a proof at that
    // position. Silently dropping the orphan would leave a released statement it can no longer
    // defend; the operator has to be told, because only they know which backup is current.
    let d = Scratch::new("orphan");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let cps = chain(&issuer, 2);
    for cp in &cps {
        cosign(&d, cp);
    }

    let seen = d.read("seen.hex");
    let first_only = seen.lines().next().expect("a line").to_string();
    std::fs::write(d.path().join("seen.hex"), first_only + "\n").expect("write");

    let (_, stderr) = exits(1, &["verify", &d.s()]);
    assert!(
        stderr.contains("CosignatureForAnotherCheckpoint"),
        "stderr was: {stderr}"
    );
}

#[test]
fn a_mixed_up_state_directory_is_caught_before_it_signs_anything() {
    // A restored `witness.key` with the old `witness.pub` left in place. Every cosignature
    // would then be attributed to a key the issuer's mirror does not list, and the failure
    // would surface as "the witness stopped working" on somebody else's phone.
    let d = Scratch::new("mixed");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let other = Scratch::new("mixed-other");
    init(&other, &issuer);
    std::fs::copy(
        other.path().join("witness.key"),
        d.path().join("witness.key"),
    )
    .expect("copy");

    let (_, stderr) = exits(1, &["status", &d.s()]);
    assert!(stderr.contains("mixed up"), "stderr was: {stderr}");
}

// ---------------------------------------------------------------------------
// What the operator is told
// ---------------------------------------------------------------------------

#[test]
fn init_says_out_loud_what_a_witness_on_this_laptop_is_worth() {
    // If this tool ever stops saying it, someone will run a witness beside their own issuer
    // and believe the resulting cosignatures mean something.
    let d = Scratch::new("custody");
    let issuer = Seeded::new(1);
    let out = run(&["init", &d.s(), "--issuer", &to_hex(&issuer.public_key())]);
    assert!(out.status.success());
    let said = String::from_utf8_lossy(&out.stderr);
    assert!(said.contains("MECHANISM TEST"));
    assert!(said.contains("DIFFERENT PARTY"));
    assert!(
        said.contains("igopay-mirror init"),
        "it must say how to register the key"
    );
}

#[cfg(unix)]
#[test]
fn the_private_key_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let d = Scratch::new("perms");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let mode = std::fs::metadata(d.path().join("witness.key"))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "witness.key was mode {mode:o}");
}

#[test]
fn status_reports_positions_the_issuer_never_offered() {
    // A witness the issuer only asks occasionally covers far less than an operator assumes.
    // Gaps are legal, so they are reported rather than refused — but they are reported.
    let d = Scratch::new("gaps");
    let issuer = Seeded::new(1);
    init(&d, &issuer);
    let cps = chain(&issuer, 5);
    cosign(&d, &cps[0]);
    cosign(&d, &cps[4]);

    let (_, report) = exits(0, &["status", &d.s()]);
    assert!(report.contains("cosigned  2 position(s)"));
    assert!(
        report.contains("3 position(s) between 0 and 4 were never offered"),
        "report was: {report}"
    );
}
