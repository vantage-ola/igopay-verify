//! `igopay-publish` — sign a block list and its checkpoint with a key this process cannot read.
//!
//! The third role, and the one that holds the system's most valuable secret. `igopay-mirror`
//! publishes and audits; `igopay-witness` attests; this signs. Three binaries because they are
//! three parties, and a tool that can do another's job is a tool that eventually will.
//!
//! **The key never enters this process.** Signing goes out to a command you configure: it
//! receives a 32-byte SHA-256 digest as hex on stdin and returns a signature as hex on stdout.
//! That makes custody a configuration choice — a Secure Enclave, a StrongBox-backed Android
//! app, a PKCS#11 token, a cloud KMS, or a human at an air-gapped machine all satisfy the same
//! seam. It is the same discipline as `igopay_core::crypto::Signer` and the mobile
//! `FfiSigner`: the code that decides is never the code that holds the key.
//!
//! Two things the seam has to fix, because they are the failure that shows up on somebody
//! else's phone weeks later:
//!
//! * **DER.** PKCS#11 and every cloud KMS return DER-encoded ECDSA. The wire format here is
//!   raw `r‖s`. Both are accepted; DER is converted.
//! * **High-S.** Nothing above guarantees low-S, and the core rejects high-S everywhere —
//!   a malleated signature over an honest artefact would otherwise be presentable as evidence
//!   against the issuer that signed it. Signatures are normalised, and then **verified against
//!   the declared public key before use**, so a misconfigured signer fails here rather than in
//!   the field.
//!
//! ```text
//! igopay-publish init     <dir> --issuer <hex> --signer <cmd>
//! igopay-publish selftest <dir>                 rehearse the signing ceremony
//! igopay-publish status   <dir>
//! igopay-publish submit   <dir> <fork-proof-hex|file>
//! igopay-publish publish  <dir> [--valid-for <secs>] [--at <unix-secs>]
//! ```
//!
//! Note what is missing: any way to block a payer by naming them. Blocking is driven by
//! `submit`, which takes a **fork proof** — two of the payer's own signatures over conflicting
//! promises. An issuer that could block by decree would be an issuer whose block list is an
//! opinion; this one can only publish arithmetic.

use std::cell::Cell;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::hex::{from_hex, hex_lines, render_lines, to_hex};
use igopay_core::{ForkProof, P256Verifier};
use igopay_issuer::mirror::{parse_checkpoints, parse_key, render_key};
use igopay_issuer::{publish_with_checkpoint, CheckpointLog, PromiseRegistry, PublishParams};

/// The public half of the publication key. Present so every command can check that what the
/// signer returns actually belongs to the identity this log is published under.
const ISSUER_KEY_FILE: &str = "issuer.pub";
/// The command that holds the key. One line, run through `sh -c`.
const SIGNER_FILE: &str = "signer.cmd";
/// Fork proofs, one hex line each: the evidence behind every blocked payer.
const PROOFS_FILE: &str = "proofs.hex";
/// This issuer's own copy of its checkpoint log, so a publication can extend it.
const LOG_FILE: &str = "checkpoints.hex";

/// Defaults for `PublishParams`. Deliberately the same shape a device expects; see
/// `igopay_issuer::PublishParams` for what each one costs.
const DEFAULT_VALID_FOR_SECS: u64 = 86_400;
const DEFAULT_BITS_PER_ITEM: usize = 12;
const DEFAULT_MIN_FILTER_BITS: usize = 512;
const DEFAULT_EXACT_RECENT: usize = 32;

macro_rules! out {
    ($($arg:tt)*) => {{
        let mut lock = std::io::stdout().lock();
        if writeln!(lock, $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

macro_rules! note {
    ($($arg:tt)*) => { eprintln!($($arg)*) };
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        usage();
        return ExitCode::from(2);
    };

    let result = match cmd {
        "init" => need_dir(&args).and_then(|d| cmd_init(&d, &args)),
        "selftest" => need_dir(&args).and_then(|d| cmd_selftest(&d)),
        "status" => need_dir(&args).and_then(|d| cmd_status(&d)),
        "submit" => need_dir(&args).and_then(|d| cmd_submit(&d, &args)),
        "publish" => need_dir(&args).and_then(|d| cmd_publish(&d, &args)),
        "-h" | "--help" | "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command `{other}`")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            note!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() {
    eprintln!(
        "igopay-publish — sign a block list and its checkpoint with a key this process cannot read

USAGE
  igopay-publish init     <dir> --issuer <hex> --signer <cmd>
  igopay-publish selftest <dir>
  igopay-publish status   <dir>
  igopay-publish submit   <dir> <fork-proof-hex|file>
  igopay-publish publish  <dir> [--valid-for <secs>] [--at <unix-secs>]

THE SIGNER
  <cmd> is run through `sh -c`. It receives a 32-byte digest as hex on stdin and must print a
  signature as hex on stdout: either raw r‖s (64 bytes) or DER. High-S is normalised, and the
  result is verified against {ISSUER_KEY_FILE} before anything is published.

  The key never enters this process. That is the point: custody is yours to choose, and this
  tool cannot leak what it cannot read."
    );
}

fn need_dir(args: &[String]) -> Result<PathBuf, String> {
    args.get(1)
        .map(PathBuf::from)
        .ok_or_else(|| "missing <dir>".to_string())
}

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn read_required(dir: &Path, name: &str) -> Result<String, String> {
    fs::read_to_string(dir.join(name)).map_err(|e| {
        format!(
            "reading {}: {e} (is {} an issuer state directory? run `init`)",
            dir.join(name).display(),
            dir.display()
        )
    })
}

fn read_optional(dir: &Path, name: &str) -> Result<String, String> {
    match fs::read_to_string(dir.join(name)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("reading {}: {e}", dir.join(name).display())),
    }
}

/// Write via a temporary file and a rename, so a crash leaves either the old file or the new
/// one. The log is what lets this issuer prove it published one history; a torn copy of it is
/// not a cosmetic problem.
fn write_atomic(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.tmp"));
    fs::write(&tmp, contents).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, dir.join(name))
        .map_err(|e| format!("replacing {}: {e}", dir.join(name).display()))
}

// ---------------------------------------------------------------------------
// The signer seam
// ---------------------------------------------------------------------------

/// A signer that runs a command instead of holding a key.
///
/// [`Signer`] is infallible by design — the core cannot return an error from the middle of
/// building an artefact — so a failure is recorded and checked afterwards, exactly as the
/// mobile FFI's `SignerAdapter` does. A publication is never emitted with a zero signature.
struct ExternalSigner {
    cmd: String,
    /// The identity this log is published under. Read from `issuer.pub`, never from the
    /// signer, so a signer that quietly changed keys is caught rather than followed.
    expected: PubKeyBytes,
    failure: Cell<Option<String>>,
    calls: Cell<usize>,
}

impl ExternalSigner {
    fn new(cmd: String, expected: PubKeyBytes) -> Self {
        ExternalSigner {
            cmd,
            expected,
            failure: Cell::new(None),
            calls: Cell::new(0),
        }
    }

    /// Record a failure, keeping the **first** one.
    ///
    /// Keeping the first matters: a publication asks for two signatures, and the first failure is
    /// the one that explains why. Getting this wrong is not cosmetic — an earlier version dropped
    /// the stored error while reading it, so two failed signatures reported as none and the tool
    /// happily emitted a block list signed with 64 zero bytes. `tests/publish.rs` pins it.
    fn fail(&self, why: String) -> SigBytes {
        let existing = self.failure.take();
        self.failure.set(existing.or(Some(why)));
        [0u8; 64]
    }

    fn failure(&self) -> Option<String> {
        let f = self.failure.take();
        self.failure.set(f.clone());
        f
    }

    /// Run the command and turn whatever it prints into a canonical low-S `r‖s` signature.
    fn try_sign(&self, digest: &[u8; 32]) -> Result<SigBytes, String> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&self.cmd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("could not run the signer command: {e}"))?;

        child
            .stdin
            .take()
            .ok_or("no stdin on the signer process")?
            .write_all(format!("{}\n", to_hex(digest)).as_bytes())
            .map_err(|e| format!("writing the digest to the signer: {e}"))?;

        let out = child
            .wait_with_output()
            .map_err(|e| format!("waiting for the signer: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "the signer exited with {}. Nothing was signed.",
                out.status.code().unwrap_or(-1)
            ));
        }

        let text = String::from_utf8_lossy(&out.stdout);
        let hex = text
            .split_whitespace()
            .next_back()
            .ok_or("the signer printed nothing")?;
        let bytes = from_hex(hex)
            .ok_or_else(|| format!("the signer printed {} which is not hex", brief(hex)))?;

        // Raw r‖s or DER — both are common, and making the operator convert would be a
        // pointless place to introduce a mistake.
        let sig = match bytes.len() {
            64 => p256::ecdsa::Signature::from_slice(&bytes)
                .map_err(|_| "the signer returned 64 bytes that are not a valid r‖s signature")?,
            _ => p256::ecdsa::Signature::from_der(&bytes).map_err(|_| {
                format!(
                    "the signer returned {} bytes: not 64-byte r‖s, and not valid DER",
                    bytes.len()
                )
            })?,
        };

        // Low-S, always. Measured to matter: Apple's own CryptoKit emits high-S about 43% of
        // the time (`research/09` §6), and a token or KMS makes no promise either way.
        let normalized: SigBytes = sig.normalize_s().unwrap_or(sig).to_bytes().into();

        // And verify it. A signer pointed at the wrong key produces artefacts that fail on
        // every device, and the whole cost of finding that out later is paid by traders.
        igopay_core::crypto::verify_p256_low_s(&self.expected, digest, &normalized).map_err(
            |_| {
                format!(
                    "the signature does not verify under {}.\n       \
                     The signer is holding a different key than {ISSUER_KEY_FILE} declares.",
                    to_hex(&self.expected)
                )
            },
        )?;

        Ok(normalized)
    }
}

impl Signer for ExternalSigner {
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        self.calls.set(self.calls.get() + 1);
        match self.try_sign(digest) {
            Ok(sig) => sig,
            Err(e) => self.fail(e),
        }
    }

    fn public_key(&self) -> PubKeyBytes {
        self.expected
    }
}

fn brief(s: &str) -> String {
    let t: String = s.chars().take(24).collect();
    if s.chars().count() > 24 {
        format!("`{t}…`")
    } else {
        format!("`{t}`")
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct State {
    issuer: PubKeyBytes,
    signer: ExternalSigner,
    log: CheckpointLog,
    proofs: Vec<ForkProof>,
}

fn load(dir: &Path) -> Result<State, String> {
    let issuer = parse_key(&read_required(dir, ISSUER_KEY_FILE)?)
        .ok_or_else(|| format!("{ISSUER_KEY_FILE} does not hold a 33-byte SEC1 public key"))?;
    let cmd = read_required(dir, SIGNER_FILE)?.trim().to_string();
    if cmd.is_empty() {
        return Err(format!(
            "{SIGNER_FILE} is empty; there is nothing to sign with"
        ));
    }

    let entries = parse_checkpoints(&read_optional(dir, LOG_FILE)?)
        .map_err(|e| format!("{LOG_FILE}: {e}"))?;
    let log = CheckpointLog::resume(issuer, entries, &P256Verifier)
        .map_err(|e| format!("this issuer's own log does not verify: {e:?}"))?;

    let mut proofs = Vec::new();
    for (line, content) in hex_lines(&read_optional(dir, PROOFS_FILE)?) {
        let bytes =
            from_hex(content).ok_or_else(|| format!("{PROOFS_FILE} line {line} is not hex"))?;
        proofs.push(
            ForkProof::from_bytes(&bytes)
                .map_err(|e| format!("{PROOFS_FILE} line {line} is not a fork proof: {e:?}"))?,
        );
    }

    Ok(State {
        issuer,
        signer: ExternalSigner::new(cmd, issuer),
        log,
        proofs,
    })
}

/// Rebuild the blocked set from the recorded evidence.
///
/// Rebuilt every time rather than cached, and every proof re-verified, so the published list is
/// a function of evidence this tool can still check — not of a summary somebody edited.
fn registry_from(state: &State) -> Result<PromiseRegistry, String> {
    let mut registry = PromiseRegistry::new(state.issuer);
    for (i, proof) in state.proofs.iter().enumerate() {
        registry
            .submit_fork_proof(proof, &P256Verifier)
            .map_err(|e| format!("{PROOFS_FILE} entry {i} no longer verifies: {e:?}"))?;
    }
    Ok(registry)
}

// ---------------------------------------------------------------------------
// init / selftest
// ---------------------------------------------------------------------------

fn cmd_init(dir: &Path, args: &[String]) -> Result<(), String> {
    let issuer_hex = flag_value(args, "--issuer").ok_or(
        "init needs --issuer <hex>: the PUBLIC half of the publication key. Get it from \
         whatever holds the private half.",
    )?;
    let issuer = parse_key(&issuer_hex).ok_or("--issuer is not a 33-byte SEC1 public key")?;
    let cmd = flag_value(args, "--signer")
        .ok_or("init needs --signer <cmd>: the command that holds the key")?;

    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if dir.join(LOG_FILE).exists() {
        return Err(format!(
            "{} already exists — init would discard a published history",
            dir.join(LOG_FILE).display()
        ));
    }

    write_atomic(dir, ISSUER_KEY_FILE, &render_key(&issuer))?;
    write_atomic(dir, SIGNER_FILE, &format!("{}\n", cmd.trim()))?;
    write_atomic(dir, PROOFS_FILE, "")?;
    write_atomic(dir, LOG_FILE, "")?;

    note!("Initialised an issuer at {}.", dir.display());
    note!("  publication key  {}", to_hex(&issuer));
    note!("  signer           {}", cmd.trim());
    note!();
    ceremony(&ExternalSigner::new(cmd.trim().to_string(), issuer))?;
    custody_warning();
    Ok(())
}

fn cmd_selftest(dir: &Path) -> Result<(), String> {
    let state = load(dir)?;
    ceremony(&state.signer)?;
    Ok(())
}

/// Rehearse the signing ceremony before anything is published.
///
/// Signs a fixed, meaningless digest and checks the result against the declared public key. It
/// exists because every way custody can be wrong — the wrong slot, the wrong key, a token that
/// needs a touch nobody is there to give, a signer that returns DER when you expected raw —
/// produces exactly one symptom otherwise: a block list that every device in the market
/// refuses, discovered by traders rather than by you.
fn ceremony(signer: &ExternalSigner) -> Result<(), String> {
    // Not a protocol digest, and deliberately not derived from anything: signing it proves
    // custody works and commits to nothing.
    let probe = [0x5au8; 32];
    note!("Rehearsing the signing ceremony (this signs a meaningless test digest)…");
    let sig = signer.sign_prehash(&probe);
    if let Some(why) = signer.failure() {
        return Err(format!("the signing ceremony FAILED.\n       {why}"));
    }
    if sig == [0u8; 64] {
        return Err("the signer returned an all-zero signature".to_string());
    }
    note!("Ceremony OK — the signer holds the declared key, and returns low-S r‖s.");
    Ok(())
}

fn custody_warning() {
    note!(
        "
Custody, plainly:
  * This key signs every block list and every checkpoint. It IS this issuer's identity. A copy
    of it is the power to block innocent payers and unblock cheats.
  * A key you cannot export is a key you cannot back up. Losing it does not invalidate anything
    already published — old artefacts keep verifying — but you can never publish again without
    re-keying every device that trusts you. Write that procedure down and rehearse it BEFORE the
    first publication, not after.
  * Keys in a Secure Enclave or StrongBox are bound to one device. Hardware Keystore was
    measured WITHOUT rollback resistance even on a StrongBox device (`research/09` §3), so a
    restored backup of the surrounding state is a real failure mode, not a theoretical one.
  * Certificates for payers do NOT have to use this key, and should not. The protocol verifies
    a certificate and a checkpoint under separately supplied keys, so registration can hold an
    online key while this one stays deliberately inconvenient."
    );
}

// ---------------------------------------------------------------------------
// status / submit
// ---------------------------------------------------------------------------

fn cmd_status(dir: &Path) -> Result<(), String> {
    let state = load(dir)?;
    let registry = registry_from(&state)?;
    note!("publication key  {}", to_hex(&state.issuer));
    note!("signer           {}", state.signer.cmd);
    note!(
        "blocked payers   {} (from {} fork proof(s))",
        registry.blocked_count(),
        state.proofs.len()
    );
    match state.log.head() {
        None => note!("head             (nothing published yet)"),
        Some(head) => note!(
            "head             seq {} epoch {} digest {}",
            head.seq,
            head.epoch,
            to_hex(&head.body_digest())
        ),
    }
    note!(
        "next publication seq {} epoch {}",
        state.log.next_seq(),
        next_epoch(&state)
    );
    Ok(())
}

fn cmd_submit(dir: &Path, args: &[String]) -> Result<(), String> {
    let arg = args.get(2).ok_or("submit needs <fork-proof-hex|file>")?;
    let bytes = read_hex_arg(arg)?;
    let proof =
        ForkProof::from_bytes(&bytes).map_err(|e| format!("not a canonical fork proof: {e:?}"))?;

    let state = load(dir)?;
    let mut registry = registry_from(&state)?;
    // Verified against this issuer's own key before it is recorded: a proof of a double spend
    // under somebody else's certificates is real, and none of this issuer's business.
    let newly = registry
        .submit_fork_proof(&proof, &P256Verifier)
        .map_err(|e| format!("refused: {e:?}"))?;

    let payer = *proof.a.payer_pubkey();
    if !newly {
        out!("{}", to_hex(&payer));
        note!("Already blocked; nothing to record.");
        return Ok(());
    }

    let mut all = state.proofs;
    all.push(proof);
    write_atomic(
        dir,
        PROOFS_FILE,
        &render_lines(all.iter().map(|p| p.encode())),
    )?;

    out!("{}", to_hex(&payer));
    note!(
        "Recorded. {} payer(s) blocked; the next `publish` will carry them.",
        registry.blocked_count()
    );
    Ok(())
}

fn read_hex_arg(arg: &str) -> Result<Vec<u8>, String> {
    if let Some(bytes) = from_hex(arg) {
        return Ok(bytes);
    }
    let text = fs::read_to_string(arg)
        .map_err(|e| format!("`{arg}` is neither hex nor a readable file: {e}"))?;
    from_hex(text.trim()).ok_or_else(|| format!("`{arg}` does not contain hex"))
}

// ---------------------------------------------------------------------------
// publish
// ---------------------------------------------------------------------------

/// The next epoch: one past the head, or 1 for a first publication.
///
/// The epoch is a device-facing rollback guard, so it only ever goes up. `CheckpointLog` refuses
/// a non-advancing epoch anyway — this just means the operator never has to supply it, and so
/// can never supply it wrongly.
fn next_epoch(state: &State) -> u64 {
    state.log.head().map_or(1, |h| h.epoch + 1)
}

fn cmd_publish(dir: &Path, args: &[String]) -> Result<(), String> {
    let valid_for = match flag_value(args, "--valid-for") {
        Some(s) => s
            .parse()
            .map_err(|_| "--valid-for must be a number of seconds")?,
        None => DEFAULT_VALID_FOR_SECS,
    };
    let issued_at = match flag_value(args, "--at") {
        Some(s) => s.parse().map_err(|_| "--at must be unix seconds")?,
        None => now(),
    };

    let mut state = load(dir)?;
    let registry = registry_from(&state)?;
    let epoch = next_epoch(&state);

    let params = PublishParams {
        epoch,
        issued_at,
        valid_for_secs: valid_for,
        bits_per_item: DEFAULT_BITS_PER_ITEM,
        min_filter_bits: DEFAULT_MIN_FILTER_BITS,
        exact_recent: DEFAULT_EXACT_RECENT,
    };

    note!(
        "Publishing epoch {epoch} at position {} with {} blocked payer(s)…",
        state.log.next_seq(),
        registry.blocked_count()
    );

    let published = publish_with_checkpoint(&registry, &params, &state.signer, &mut state.log)
        .map_err(|e| format!("the publication was refused: {e:?}"))?;
    // Checked after, because `Signer` cannot fail mid-artefact. Two signatures were requested
    // (the list, then the checkpoint); either failing means nothing here is publishable.
    if let Some(why) = state.signer.failure() {
        return Err(format!(
            "signing failed after {} request(s), so NOTHING was written.\n       {why}",
            state.signer.calls.get()
        ));
    }

    // Then check the output the way a phone will, before anything leaves this process: the
    // issuer's signature on the checkpoint, the issuer's signature on the list, and the
    // commitment binding one to the other. If a device would refuse it, this tool refuses to
    // publish it.
    //
    // Belt and braces on purpose. The failure flag above is the primary guard, and it was once
    // wrong — a bug that emitted a list signed with 64 zero bytes. A publication is the one place
    // in this system where paranoia is free, because it happens twice a day.
    igopay_core::install_checkpointed_list(
        &published.list,
        &published.checkpoint,
        &state.issuer,
        &P256Verifier,
        None,
    )
    .map_err(|e| {
        format!(
            "the artefacts this produced would be REFUSED by a device ({e:?}), so nothing was \
             written. That is a custody or signer problem, not a protocol one."
        )
    })?;

    // The local log is written before the artefacts are printed. An issuer that emitted a
    // checkpoint it then forgot would offer the same position again next time — which is
    // equivocation, done by accident, and provable against it forever.
    write_atomic(
        dir,
        LOG_FILE,
        &render_lines(state.log.entries().iter().map(|c| c.encode())),
    )?;

    note!(
        "Signed. position {} epoch {} digest {}",
        published.checkpoint.seq,
        published.checkpoint.epoch,
        to_hex(&published.checkpoint.body_digest())
    );
    note!();
    note!("--- block list (distribute to devices) ---");
    out!("{}", to_hex(&published.list.encode()));
    note!("--- checkpoint (append to the public mirror) ---");
    out!("{}", to_hex(&published.checkpoint.encode()));
    note!(
        "
Next, by hand:
  igopay-mirror append <mirror> <the checkpoint hex above>
  igopay-witness cosign <witness-state> <the checkpoint hex above>   # then: igopay-mirror attest
  igopay-mirror verify <mirror> && ots stamp <mirror>/head.txt

The block list is NOT mirrored, deliberately: it carries blocked payers' public keys, and
publishing it would mean publishing a permanent world-readable blacklist."
    );
    Ok(())
}
