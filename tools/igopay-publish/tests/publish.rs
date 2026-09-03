//! End-to-end publication, driving the real binary with a real external signer.
//!
//! The signer here is **openssl**, chosen deliberately rather than for convenience: it returns
//! **DER** and makes no low-S promise, so these tests exercise the two conversions that stand
//! between a custody choice and artefacts a phone will accept. Those are the failures that
//! otherwise surface weeks later on somebody else's device.
//!
//! What is NOT tested here is the Secure Enclave path — it needs Apple hardware and a human
//! touching a sensor, so it is exercised by hand (see the crate docs). The seam is identical, and
//! that is the point of it being a command rather than a library.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::{
    build_certificate, detect_fork, from_hex, install_checkpointed_list, to_hex, Checkpoint,
    P256Verifier, PaymentDetails, PromiseBuilder, SignedBlockList, SlotGrant,
};

const BIN: &str = env!("CARGO_BIN_EXE_igopay-publish");

// ---------------------------------------------------------------------------
// A scratch issuer whose key openssl holds
// ---------------------------------------------------------------------------

struct Issuer {
    dir: std::path::PathBuf,
    pubkey: PubKeyBytes,
    /// The same key loaded into Rust — used only to sign the *certificates* a fork proof needs.
    /// The publisher under test never gets this; it goes through the signer script.
    inner: p256::ecdsa::SigningKey,
}

impl Issuer {
    fn new(name: &str) -> Self {
        let dir =
            std::env::temp_dir().join(format!("igopay-publish-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("mkdir");

        let pem = dir.join("key.pem");
        sh(&format!(
            "openssl ecparam -genkey -name prime256v1 -noout -out {}",
            pem.display()
        ));

        // The compressed SEC1 public key is the last 33 bytes of the DER SubjectPublicKeyInfo.
        let pk_hex = sh(&format!(
            "openssl ec -in {} -pubout -conv_form compressed -outform DER 2>/dev/null \
             | xxd -p | tr -d '\\n' | tail -c 66",
            pem.display()
        ));
        let pubkey: PubKeyBytes = from_hex(pk_hex.trim())
            .expect("hex")
            .as_slice()
            .try_into()
            .expect("33 bytes");

        // Pull the same scalar into Rust. Test-only: it is how a fork proof's certificates get
        // issuer-signed without routing certificate issuance through this tool, which does not
        // do certificates.
        let priv_hex = sh(&format!(
            "openssl ec -in {} -text -noout 2>/dev/null \
             | awk '/priv:/{{f=1;next}} /pub:/{{f=0}} f' | tr -d ' :\\n'",
            pem.display()
        ));
        // Take the trailing 64 hex characters: openssl sometimes prints a leading zero byte for
        // the ASN.1 integer, and the scalar is what the last 32 bytes hold either way.
        let trimmed = priv_hex.trim();
        let tail = &trimmed[trimmed.len().saturating_sub(64)..];
        let scalar: [u8; 32] = from_hex(tail)
            .expect("hex")
            .as_slice()
            .try_into()
            .expect("32-byte scalar");
        let inner = p256::ecdsa::SigningKey::from_bytes(&scalar.into()).expect("valid scalar");
        assert_eq!(
            compressed(&inner),
            pubkey,
            "the scalar read back from openssl must be the same key"
        );

        Issuer { dir, pubkey, inner }
    }

    /// A signer command in the shape `igopay-publish` expects: digest hex in, signature hex out.
    ///
    /// openssl's `pkeyutl -sign` on a 32-byte input signs it as a digest, which is exactly
    /// `Signer::sign_prehash`. It emits DER and does not normalise S.
    fn signer_cmd(&self) -> String {
        format!(
            "read d; printf '%s' \"$d\" | xxd -r -p > {tmp}; \
             openssl pkeyutl -sign -inkey {pem} -in {tmp} | xxd -p | tr -d '\\n'",
            tmp = self.dir.join("digest.bin").display(),
            pem = self.dir.join("key.pem").display()
        )
    }

    /// A signer that holds a *different* key, for the check that matters most.
    fn wrong_key_cmd(&self) -> String {
        let other = self.dir.join("other.pem");
        sh(&format!(
            "openssl ecparam -genkey -name prime256v1 -noout -out {}",
            other.display()
        ));
        format!(
            "read d; printf '%s' \"$d\" | xxd -r -p > {tmp}; \
             openssl pkeyutl -sign -inkey {other} -in {tmp} | xxd -p | tr -d '\\n'",
            tmp = self.dir.join("digest2.bin").display(),
            other = other.display()
        )
    }

    fn state(&self) -> String {
        self.dir.join("issuer").display().to_string()
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Issuer {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn compressed(sk: &p256::ecdsa::SigningKey) -> PubKeyBytes {
    sk.verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("33 bytes")
}

/// The issuer key as a core `Signer`, for issuing the certificates a fork proof needs.
struct IssuerSigner<'a>(&'a p256::ecdsa::SigningKey);

impl Signer for IssuerSigner<'_> {
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).expect("sign");
        sig.normalize_s().unwrap_or(sig).to_bytes().into()
    }

    fn public_key(&self) -> PubKeyBytes {
        compressed(self.0)
    }
}

struct Seeded(p256::ecdsa::SigningKey);

impl Seeded {
    fn new(seed: u8) -> Self {
        let mut b = [0u8; 32];
        b[31] = seed.max(1);
        Seeded(p256::ecdsa::SigningKey::from_bytes(&b.into()).expect("scalar"))
    }
}

impl Signer for Seeded {
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.0.sign_prehash(digest).expect("sign");
        sig.normalize_s().unwrap_or(sig).to_bytes().into()
    }

    fn public_key(&self) -> PubKeyBytes {
        compressed(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn sh(cmd: &str) -> String {
    let out = Command::new("sh").arg("-c").arg(cmd).output().expect("sh");
    assert!(
        out.status.success(),
        "shell command failed: {cmd}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("runs")
}

fn ok(args: &[&str]) -> (String, String) {
    let out = run(args);
    assert!(
        out.status.success(),
        "expected success from {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn fails(args: &[&str]) -> String {
    let out = run(args);
    assert!(
        !out.status.success(),
        "expected failure from {args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn init(issuer: &Issuer) -> (String, String) {
    ok(&[
        "init",
        &issuer.state(),
        "--issuer",
        &to_hex(&issuer.pubkey),
        "--signer",
        &issuer.signer_cmd(),
    ])
}

/// `publish` prints the block list on the first stdout line and the checkpoint on the second.
fn publish(issuer: &Issuer) -> (SignedBlockList, Checkpoint) {
    let (stdout, _) = ok(&["publish", &issuer.state()]);
    let mut lines = stdout.lines();
    let list = SignedBlockList::decode(&from_hex(lines.next().expect("list line")).expect("hex"))
        .expect("canonical list");
    let cp = Checkpoint::from_bytes(&from_hex(lines.next().expect("cp line")).expect("hex"))
        .expect("canonical checkpoint");
    (list, cp)
}

// ---------------------------------------------------------------------------
// The ceremony
// ---------------------------------------------------------------------------

#[test]
fn init_rehearses_the_signing_ceremony_before_anything_is_published() {
    let issuer = Issuer::new("ceremony");
    let (_, said) = init(&issuer);
    assert!(said.contains("Ceremony OK"), "stderr was: {said}");
    assert!(
        said.contains("Custody, plainly"),
        "init must say what holding this key means"
    );
    // The state exists and is empty.
    assert_eq!(
        fs::read_to_string(issuer.path().join("issuer/checkpoints.hex")).unwrap(),
        ""
    );
}

#[test]
fn a_signer_holding_the_wrong_key_is_caught_at_init_not_in_the_market() {
    // The load-bearing test for this whole tool. Every way custody can be misconfigured — wrong
    // slot, wrong key, wrong file — produces one symptom otherwise: a block list that every
    // device refuses, discovered by traders. The ceremony turns that into a failed `init`.
    let issuer = Issuer::new("wrongkey");
    let said = fails(&[
        "init",
        &issuer.state(),
        "--issuer",
        &to_hex(&issuer.pubkey),
        "--signer",
        &issuer.wrong_key_cmd(),
    ]);
    assert!(said.contains("ceremony FAILED"), "stderr was: {said}");
    assert!(
        said.contains("different key"),
        "the message must say what is actually wrong: {said}"
    );
}

#[test]
fn a_signer_that_cannot_run_is_a_failed_ceremony_and_not_a_publication() {
    // A separate state directory per case: `init` refuses to run twice over one, which is itself
    // the guard against discarding a published history.
    for (n, cmd) in [("exit7", "exit 7"), ("junk", "echo not-a-signature")] {
        let issuer = Issuer::new(&format!("nosigner-{n}"));
        let said = fails(&[
            "init",
            &issuer.state(),
            "--issuer",
            &to_hex(&issuer.pubkey),
            "--signer",
            cmd,
        ]);
        assert!(said.contains("ceremony FAILED"), "`{cmd}` gave: {said}");
    }
}

// ---------------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------------

#[test]
fn a_published_list_and_checkpoint_are_what_a_device_installs() {
    // The only assertion that really matters: what comes out of this tool goes through the
    // device-side install path in the core, unmodified.
    let issuer = Issuer::new("install");
    init(&issuer);
    let (list, cp) = publish(&issuer);

    assert_eq!(cp.seq, 0);
    assert_eq!(cp.epoch, 1);
    assert!(cp.is_genesis(), "the first checkpoint must be genesis");

    let installed = install_checkpointed_list(&list, &cp, &issuer.pubkey, &P256Verifier, None)
        .expect("a device installs it");
    assert_eq!(installed.epoch(), 1);
    assert_eq!(installed.exact_count(), 0, "nobody is blocked yet");
}

#[test]
fn successive_publications_advance_the_epoch_and_link_the_chain() {
    // openssl does not normalise S, so across four publications (eight signatures) high-S
    // results are near-certain. Every artefact still verifying is the proof that the tool's
    // normalisation is doing its job rather than getting lucky.
    let issuer = Issuer::new("chain");
    init(&issuer);

    let mut prev: Option<Checkpoint> = None;
    for expected_epoch in 1..=4u64 {
        let (list, cp) = publish(&issuer);
        assert_eq!(cp.epoch, expected_epoch);
        assert_eq!(cp.seq, expected_epoch - 1);
        install_checkpointed_list(&list, &cp, &issuer.pubkey, &P256Verifier, None)
            .expect("installs");
        if let Some(p) = &prev {
            assert_eq!(
                cp.prev_hash,
                p.body_digest(),
                "position {} must name position {}",
                cp.seq,
                p.seq
            );
        }
        prev = Some(cp);
    }

    let (_, said) = ok(&["status", &issuer.state()]);
    assert!(said.contains("head             seq 3 epoch 4"), "{said}");
    assert!(said.contains("next publication seq 4 epoch 5"), "{said}");
}

#[test]
fn a_signer_that_fails_mid_publication_writes_nothing() {
    // An issuer that emitted a checkpoint it then forgot would offer the same position again
    // next time. That is equivocation by accident, and it is provable against the issuer
    // forever — so a failed signature has to leave the log exactly as it was.
    let issuer = Issuer::new("midfail");
    init(&issuer);
    publish(&issuer); // one good publication, so there is something to lose
    let before = fs::read_to_string(issuer.path().join("issuer/checkpoints.hex")).unwrap();

    // Break the signer after the fact: the state directory keeps the command, so rewrite it.
    fs::write(issuer.path().join("issuer/signer.cmd"), "exit 3\n").unwrap();
    let said = fails(&["publish", &issuer.state()]);
    assert!(
        said.contains("NOTHING was written") || said.contains("signing failed"),
        "stderr was: {said}"
    );
    assert_eq!(
        fs::read_to_string(issuer.path().join("issuer/checkpoints.hex")).unwrap(),
        before,
        "the log must be untouched"
    );
}

#[test]
fn a_tampered_local_log_stops_publication_rather_than_forking_it() {
    let issuer = Issuer::new("tampered");
    init(&issuer);
    publish(&issuer);

    let path = issuer.path().join("issuer/checkpoints.hex");
    let line = fs::read_to_string(&path).unwrap().trim().to_string();
    fs::write(&path, format!("{}deadbeef\n", &line[..line.len() - 8])).unwrap();

    let said = fails(&["publish", &issuer.state()]);
    assert!(said.contains("does not verify"), "stderr was: {said}");
}

// ---------------------------------------------------------------------------
// Blocking requires evidence
// ---------------------------------------------------------------------------

/// Two conflicting promises at one `seq` under a certificate this issuer signed.
fn fork_proof_for(issuer: &Issuer, payer_seed: u8) -> igopay_core::ForkProof {
    let issuer_signer = IssuerSigner(&issuer.inner);
    let payer = Seeded::new(payer_seed);
    let payee_a = Seeded::new(200);
    let payee_b = Seeded::new(201);

    let cert = build_certificate(
        &issuer_signer,
        payer.public_key(),
        "test".to_string(),
        1,
        100_000,
        SlotGrant {
            from: 1_700_000_000,
            to: 1_700_100_000,
            granularity_secs: 60,
        },
        0,
        1_699_000_000,
        1_800_000_000,
    );

    let payment = |payee: PubKeyBytes| PaymentDetails {
        payee_pubkey: payee,
        amount: 500,
        currency: "NGN".to_string(),
        nonce: vec![0u8; 12],
        slot: 1_700_000_040,
    };
    let a = PromiseBuilder::fresh(&payer, cert.clone()).sign_next(payment(payee_a.public_key()));
    let b = PromiseBuilder::fresh(&payer, cert).sign_next(payment(payee_b.public_key()));
    detect_fork(&a, &b).expect("two payees at one seq is a fork")
}

#[test]
fn a_payer_can_only_be_blocked_with_a_fork_proof_and_it_reaches_the_next_list() {
    // The property worth protecting: an issuer that could block by decree would be publishing
    // an opinion. This one can only publish arithmetic.
    let issuer = Issuer::new("blocking");
    init(&issuer);
    publish(&issuer);

    assert!(
        fails(&["submit", &issuer.state(), "deadbeef"]).contains("not a canonical fork proof"),
        "junk must be refused"
    );

    let proof = fork_proof_for(&issuer, 42);
    let (stdout, said) = ok(&["submit", &issuer.state(), &to_hex(&proof.encode())]);
    assert!(said.contains("1 payer(s) blocked"), "{said}");
    let blocked: PubKeyBytes = from_hex(stdout.trim())
        .expect("hex")
        .as_slice()
        .try_into()
        .expect("33 bytes");

    // Submitting the same evidence again is not a second block.
    let (_, said) = ok(&["submit", &issuer.state(), &to_hex(&proof.encode())]);
    assert!(said.contains("Already blocked"), "{said}");

    // And the next publication carries them, verifiably, through the device path.
    let (list, cp) = publish(&issuer);
    let installed = install_checkpointed_list(&list, &cp, &issuer.pubkey, &P256Verifier, None)
        .expect("installs");
    assert_eq!(installed.exact_count(), 1);
    assert!(
        installed.contains_exact(&blocked),
        "the blocked payer must be in the exact set, not merely the filter"
    );
}

#[test]
fn a_fork_proof_under_another_issuers_certificates_is_refused() {
    // Real evidence of a real double spend, and none of this issuer's business: acting on it
    // would mean blocking a payer this issuer never certified.
    let ours = Issuer::new("ours");
    let theirs = Issuer::new("theirs");
    init(&ours);
    let said = fails(&[
        "submit",
        &ours.state(),
        &to_hex(&fork_proof_for(&theirs, 43).encode()),
    ]);
    assert!(said.contains("refused"), "stderr was: {said}");
}
