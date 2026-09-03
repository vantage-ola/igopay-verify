//! End-to-end publication loop, driving the real binary.
//!
//! The format's rules are proved in `igopay-issuer/tests/mirror.rs`. What this covers is the
//! part that only exists here: that the commands compose into a working loop, that `verify`
//! fails loudly on a mirror an auditor should reject, and that a bad publication can never be
//! written — because `append` refuses anything `verify` would refuse.

use std::path::Path;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_igopay-mirror");

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

fn fails(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}\nstdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// A scratch directory that cleans itself up.
struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("igopay-mirror-test-{name}-{}", std::process::id()));
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
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn line(path: &Path, n: usize) -> String {
    std::fs::read_to_string(path)
        .expect("read")
        .lines()
        .nth(n)
        .expect("line")
        .to_string()
}

#[test]
fn a_demo_mirror_verifies_and_declares_itself_a_demo() {
    let d = Scratch::new("demo");
    ok(&["demo", &d.s(), "3"]);

    let report = ok(&["verify", &d.s()]);
    assert!(report.contains("entries  3"));
    assert!(report.contains("3/3 position(s) attested"));
    assert!(
        report.contains("THIS-IS-A-DEMO"),
        "a demo mirror must say so; throwaway keys must never be mistaken for an issuer"
    );

    // The head command prints exactly the digest, so it can be piped straight to a timestamper.
    let head = ok(&["head", &d.s()]);
    assert_eq!(head.trim().len(), 64);
    assert!(report.contains(head.trim()));
}

#[test]
fn verify_refuses_every_mirror_an_auditor_should_reject() {
    let d = Scratch::new("bad");
    ok(&["demo", &d.s(), "4"]);
    let checkpoints = d.path().join("checkpoints.hex");
    let original = std::fs::read_to_string(&checkpoints).expect("read");

    // A tampered entry: still well-formed, no longer signed.
    let mut lines: Vec<String> = original.lines().map(String::from).collect();
    let target = lines[2].clone();
    lines[2] = format!("{}deadbeef", &target[..target.len() - 8]);
    std::fs::write(&checkpoints, lines.join("\n") + "\n").expect("write");
    assert!(fails(&["verify", &d.s()]).contains("does not verify"));

    // A dropped entry.
    let dropped: Vec<&str> = original
        .lines()
        .filter(|l| l != &original.lines().nth(1).unwrap())
        .collect();
    std::fs::write(&checkpoints, dropped.join("\n") + "\n").expect("write");
    assert!(fails(&["verify", &d.s()]).contains("dropped, added or reordered"));

    // A head that names something other than the last entry.
    std::fs::write(&checkpoints, &original).expect("restore");
    let head_file = d.path().join("head.txt");
    let head = std::fs::read_to_string(&head_file).expect("read");
    let flipped = format!("f{}", &head.trim()[1..]);
    std::fs::write(&head_file, flipped + "\n").expect("write");
    let err = fails(&["verify", &d.s()]);
    assert!(err.contains("head names"), "got: {err}");
}

#[test]
fn the_publication_loop_composes() {
    // Two demo mirrors from the same fixed seeds: the fourth entry of the longer one
    // legitimately extends the shorter one's log, which is the shape a real service produces.
    let short = Scratch::new("short");
    let long = Scratch::new("long");
    ok(&["demo", &short.s(), "3"]);
    ok(&["demo", &long.s(), "4"]);

    let next = line(&long.path().join("checkpoints.hex"), 3);
    let attestation = line(&long.path().join("cosignatures.hex"), 3);

    ok(&["append", &short.s(), &next]);
    let after_append = ok(&["verify", &short.s()]);
    assert!(after_append.contains("entries  4"));
    assert!(
        after_append.contains("unattested positions: 3"),
        "a freshly published head is not yet attested; got: {after_append}"
    );

    ok(&["attest", &short.s(), &attestation]);
    assert!(ok(&["verify", &short.s()]).contains("4/4 position(s) attested"));

    // Recording the same attestation twice is a no-op, not a duplicated line.
    let before = std::fs::read_to_string(short.path().join("cosignatures.hex")).unwrap();
    ok(&["attest", &short.s(), &attestation]);
    assert_eq!(
        before,
        std::fs::read_to_string(short.path().join("cosignatures.hex")).unwrap()
    );
}

#[test]
fn append_refuses_what_verify_would_refuse() {
    let ours = Scratch::new("ours");
    let theirs = Scratch::new("theirs");
    ok(&["demo", &ours.s(), "2"]);
    ok(&["demo", &theirs.s(), "2"]);

    // Position 0 again: an entry that does not extend the log.
    let genesis = line(&theirs.path().join("checkpoints.hex"), 0);
    assert!(fails(&["append", &ours.s(), &genesis]).contains("does not extend"));

    // Junk, and a file that is not hex.
    assert!(!fails(&["append", &ours.s(), "not-hex"]).is_empty());

    // The mirror is untouched by either refusal.
    assert!(ok(&["verify", &ours.s()]).contains("entries  2"));
}

#[test]
fn attest_refuses_an_attestation_it_cannot_credit() {
    let d = Scratch::new("attest");
    let other = Scratch::new("attest-other");
    ok(&["demo", &d.s(), "2"]);
    ok(&["demo", &other.s(), "3"]);

    // A cosignature for a checkpoint this mirror has not published.
    let future = line(&other.path().join("cosignatures.hex"), 2);
    assert!(fails(&["attest", &d.s(), &future]).contains("not in the published log"));

    // With no witnesses listed, nothing can be credited — and the message says to add the key
    // deliberately rather than silently accepting it.
    let witnesses = d.path().join("witnesses.txt");
    let saved = std::fs::read_to_string(&witnesses).unwrap();
    std::fs::write(&witnesses, "").unwrap();
    let cosig = line(&other.path().join("cosignatures.hex"), 0);
    assert!(fails(&["attest", &d.s(), &cosig]).contains("witnesses.txt"));
    std::fs::write(&witnesses, saved).unwrap();
}

#[test]
fn init_lays_down_an_empty_mirror_and_will_not_clobber_one() {
    let src = Scratch::new("init-src");
    let d = Scratch::new("init");
    ok(&["demo", &src.s(), "1"]);
    let issuer = std::fs::read_to_string(src.path().join("issuer.pub")).unwrap();
    let target = d.path().join("fresh");
    let target_s = target.display().to_string();

    ok(&["init", &target_s, "--issuer", issuer.trim()]);
    let report = ok(&["verify", &target_s]);
    assert!(report.contains("entries  0"));
    assert!(report.contains("nothing published yet"));
    assert!(target.join("README.md").exists());
    assert!(
        std::fs::read_to_string(target.join("README.md"))
            .unwrap()
            .contains("What this does not prove"),
        "the mirror's README must state its limits, not just its claims"
    );

    // A second init would overwrite a published log.
    assert!(fails(&["init", &target_s, "--issuer", issuer.trim()]).contains("already exists"));
}

#[test]
fn usage_errors_are_usage_errors_not_crashes() {
    assert!(!run(&[]).status.success());
    assert!(!fails(&["verify"]).is_empty());
    assert!(!fails(&["verify", "/nonexistent/mirror"]).is_empty());
    assert!(!fails(&["wat", "/tmp"]).is_empty());
    assert!(run(&["--help"]).status.success());
}
