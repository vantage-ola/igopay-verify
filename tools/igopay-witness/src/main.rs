//! `igopay-witness` — the second signature on the issuer's history.
//!
//! B7's other half. `igopay-mirror` publishes the issuer's checkpoint log so that
//! equivocation becomes *provable once two views are compared*; this tool is the party that
//! makes the comparison happen **before** the payment, not after. It holds a witness key and
//! a memory of every position it has attested to, and it enforces one rule:
//!
//! > at most one head per log position, ever.
//!
//! The cosignature it emits travels *with* the checkpoint, over the same carried-by-hand
//! transport as the block list, so a payee with no connectivity can check it at the counter.
//! That is the difference between detecting a split view next week and refusing it now.
//!
//! **This tool implements nothing.** The rule, the comparison and every signature check live
//! in `igopay_core::witness::WitnessLog`; here there is file I/O and printing. It also does
//! not link `igopay-issuer` — a witness carrying the issuer's code would make the separation
//! this whole mechanism rests on a naming convention rather than a fact.
//!
//! ```text
//! igopay-witness init   <dir> --issuer <hex>       generate a key, start a log
//! igopay-witness pubkey <dir>                      the key to hand the issuer
//! igopay-witness status <dir>                      who this is, and what it has signed
//! igopay-witness cosign <dir> <checkpoint-hex|file>   the one verb that matters
//! igopay-witness check  <dir> <checkpoint-hex|file>   does this head contradict mine?
//! igopay-witness verify <dir>                      re-verify this witness's own state
//! ```
//!
//! `cosign`, `check` and `pubkey` write **only the artefact** to stdout, so they pipe. The
//! checkpoint to cosign is the last line of the mirror's log:
//!
//! ```text
//! tail -1 ./mirror/checkpoints.hex \
//!   | xargs igopay-witness cosign ./witness-state \
//!   | xargs igopay-mirror attest ./mirror
//! ```
//!
//! Exit codes: `0` fine, `1` error, `3` a *proven conflict* (an equivocation proof was
//! printed — publish it), `4` this witness has nothing to say about that position.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use igopay_core::checkpoint::{Checkpoint, EquivocationProof};
use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::hex::{from_hex, hex_lines, render_lines, to_hex};
use igopay_core::witness::{Cosignature, WitnessLog, WitnessRefusal, WitnessedCheckpoint};
use igopay_core::P256Verifier;

/// The issuer whose history this witness watches. Its own file, so that pointing a witness at
/// a different issuer is a visible, deliberate edit rather than a flag someone mistyped once.
const ISSUER_KEY_FILE: &str = "issuer.pub";
/// This witness's public key — the value the issuer puts in the mirror's `witnesses.txt`.
const WITNESS_PUB_FILE: &str = "witness.pub";
/// This witness's **private** key. See [`custody_warning`].
const WITNESS_KEY_FILE: &str = "witness.key";
/// Every checkpoint this witness has accepted, one hex line each, ascending by position.
const SEEN_FILE: &str = "seen.hex";
/// Every cosignature this witness has issued, one hex line each, ascending by position.
const ISSUED_FILE: &str = "issued.hex";

const EXIT_CONFLICT: u8 = 3;
const EXIT_UNKNOWN: u8 = 4;

/// Print an artefact or report to stdout, treating a closed pipe as a normal end.
///
/// Same reasoning as `igopay-mirror`: the obvious way to use this tool is to pipe it into
/// something else, and a default `println!` panics with `Broken pipe` when that something
/// stops reading.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let mut lock = std::io::stdout().lock();
        if writeln!(lock, $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

/// Print commentary to stderr, so stdout stays exactly one artefact.
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
        "pubkey" => need_dir(&args).and_then(|d| cmd_pubkey(&d)),
        "status" => need_dir(&args).and_then(|d| cmd_status(&d)),
        "cosign" => need_dir(&args).and_then(|d| cmd_cosign(&d, &args)),
        "check" => need_dir(&args).and_then(|d| cmd_check(&d, &args)),
        "verify" => need_dir(&args).and_then(|d| cmd_verify(&d)),
        "-h" | "--help" | "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command `{other}`")),
    };

    match result {
        Ok(code) => code,
        Err(e) => {
            note!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() {
    eprintln!(
        "igopay-witness — cosign one head per issuer log position (B7)

USAGE
  igopay-witness init   <dir> --issuer <hex>
  igopay-witness pubkey <dir>
  igopay-witness status <dir>
  igopay-witness cosign <dir> <checkpoint-hex|file>
  igopay-witness check  <dir> <checkpoint-hex|file>
  igopay-witness verify <dir>

<dir> holds this witness's key and its memory. The memory is not optional: a witness that
forgets a position can be talked into cosigning a second head there, which is the exact
failure it exists to prevent.

stdout carries only the artefact (a cosignature, a proof, a key); everything else is stderr.

EXIT CODES
  0  fine          1  error
  3  a conflict was PROVEN — an equivocation proof is on stdout. Publish it.
  4  this witness has nothing to say about that position."
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

// ---------------------------------------------------------------------------
// Files. Nothing clever, but the write ORDER is load-bearing — see `save`.
// ---------------------------------------------------------------------------

fn read_optional(dir: &Path, name: &str) -> Result<String, String> {
    match fs::read_to_string(dir.join(name)) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("reading {}: {e}", dir.join(name).display())),
    }
}

fn read_required(dir: &Path, name: &str) -> Result<String, String> {
    fs::read_to_string(dir.join(name)).map_err(|e| {
        format!(
            "reading {}: {e} (is {} a witness state directory? run `init`)",
            dir.join(name).display(),
            dir.display()
        )
    })
}

/// Write via a temporary file and a rename.
///
/// A witness's state file is the only thing standing between it and cosigning a second head,
/// so a half-written one is not an inconvenience. `rename` within a directory is atomic, so a
/// crash leaves either the old file or the new one.
fn write_atomic(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let tmp = dir.join(format!("{name}.tmp"));
    let dst = dir.join(name);
    fs::write(&tmp, contents).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    fs::rename(&tmp, &dst).map_err(|e| format!("replacing {}: {e}", dst.display()))
}

/// Create the private-key file, refusing to overwrite one, and never briefly world-readable.
#[cfg(unix)]
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true) // also how `init` refuses to clobber an existing witness
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("creating {}: {e}", path.display()))?;
    f.write_all(contents.as_bytes())
        .map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    if path.exists() {
        return Err(format!("{} already exists", path.display()));
    }
    note!(
        "warning: cannot set 0600 permissions on this platform; check {} by hand",
        path.display()
    );
    fs::write(path, contents).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Complain if the key file is readable by anyone else. A warning rather than a refusal: the
/// operator may have a reason, and a tool that refuses to start is a tool that gets replaced
/// by a shell script that does not check at all.
#[cfg(unix)]
fn check_key_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(md) = fs::metadata(path) {
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            note!(
                "warning: {} is mode {mode:o} — readable beyond its owner. `chmod 600` it.",
                path.display()
            );
        }
    }
}

#[cfg(not(unix))]
fn check_key_permissions(_path: &Path) {}

// ---------------------------------------------------------------------------
// Parsing. Container only: everything below is handed to the library to verify.
// ---------------------------------------------------------------------------

fn parse_pubkey(text: &str, what: &str) -> Result<PubKeyBytes, String> {
    let (_, line) = hex_lines(text)
        .next()
        .ok_or_else(|| format!("{what} is empty"))?;
    let bytes = from_hex(line).ok_or_else(|| format!("{what} is not hex"))?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{what} is not a 33-byte SEC1 compressed public key"))
}

/// Checkpoints from `seen.hex`.
///
/// Unlike the issuer's mirror, this does **not** require position `n` on line `n`. A witness
/// legitimately has gaps: it may be shown position 7 having never been shown 6, because it
/// was offline or because the issuer only ever asks it about the current head. Requiring
/// contiguity here would turn a normal Tuesday into a corrupt state file.
fn parse_seen(text: &str) -> Result<Vec<Checkpoint>, String> {
    let mut out = Vec::new();
    for (line, content) in hex_lines(text) {
        let bytes =
            from_hex(content).ok_or_else(|| format!("{SEEN_FILE} line {line} is not hex"))?;
        let cp = Checkpoint::from_bytes(&bytes)
            .map_err(|e| format!("{SEEN_FILE} line {line} is not a canonical checkpoint: {e:?}"))?;
        out.push(cp);
    }
    out.sort_by_key(|c| c.seq);
    Ok(out)
}

fn parse_issued(text: &str) -> Result<Vec<Cosignature>, String> {
    let mut out = Vec::new();
    for (line, content) in hex_lines(text) {
        let bytes =
            from_hex(content).ok_or_else(|| format!("{ISSUED_FILE} line {line} is not hex"))?;
        let c = Cosignature::from_bytes(&bytes).map_err(|e| {
            format!("{ISSUED_FILE} line {line} is not a canonical cosignature: {e:?}")
        })?;
        out.push(c);
    }
    Ok(out)
}

/// Read a checkpoint given inline hex or a path, in either the bare or the witnessed form.
///
/// Both forms, because the issuer may hand over what it distributes — a checkpoint that
/// already carries somebody else's cosignatures — and refusing that would make the operator
/// hand-edit an artefact, which is how mistakes happen. Only the checkpoint inside is used.
fn read_checkpoint_arg(arg: &str) -> Result<Checkpoint, String> {
    let bytes = match from_hex(arg) {
        Some(b) => b,
        None => {
            let text = fs::read_to_string(arg)
                .map_err(|e| format!("`{arg}` is neither hex nor a readable file: {e}"))?;
            from_hex(text.trim()).ok_or_else(|| format!("`{arg}` does not contain hex"))?
        }
    };
    if let Ok(cp) = Checkpoint::from_bytes(&bytes) {
        return Ok(cp);
    }
    WitnessedCheckpoint::from_bytes(&bytes)
        .map(|w| w.checkpoint)
        .map_err(|e| format!("not a canonical checkpoint or witnessed checkpoint: {e:?}"))
}

// ---------------------------------------------------------------------------
// The key. On disk, in the clear, and the tool says so.
// ---------------------------------------------------------------------------

/// A witness key loaded from a file.
///
/// The production shape of this is a platform keystore behind
/// [`igopay_core::crypto::Signer`] — the same trait, a different implementation, which is why
/// the library never needed to know the difference. A file-backed key is for rehearsing the
/// loop on a laptop.
struct WitnessKey {
    sk: p256::ecdsa::SigningKey,
}

impl WitnessKey {
    /// A fresh key from the OS CSPRNG, by rejection sampling.
    ///
    /// `/dev/urandom` directly rather than a random-number crate: this tool's dependency list
    /// is two entries and worth keeping that way, and `SigningKey::from_bytes` already does
    /// the only validation that matters (in range, non-zero) — so the loop is the standard
    /// rejection sampler rather than anything invented here.
    fn generate() -> Result<Self, String> {
        let mut src =
            fs::File::open("/dev/urandom").map_err(|e| format!("opening /dev/urandom: {e}"))?;
        for _ in 0..64 {
            let mut bytes = [0u8; 32];
            src.read_exact(&mut bytes)
                .map_err(|e| format!("reading /dev/urandom: {e}"))?;
            // No scrubbing of `bytes` here, deliberately: this key is about to be written to
            // disk in the clear, so wiping a stack copy would be theatre. The fix for that is
            // a keystore, not a memset.
            if let Ok(sk) = p256::ecdsa::SigningKey::from_bytes(&bytes.into()) {
                return Ok(WitnessKey { sk });
            }
        }
        Err(
            "could not draw a valid P-256 scalar in 64 attempts — that should be impossible; \
             check /dev/urandom"
                .to_string(),
        )
    }

    fn from_hex_text(text: &str) -> Result<Self, String> {
        let (_, line) = hex_lines(text)
            .next()
            .ok_or_else(|| format!("{WITNESS_KEY_FILE} is empty"))?;
        let bytes = from_hex(line).ok_or_else(|| format!("{WITNESS_KEY_FILE} is not hex"))?;
        let scalar: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| format!("{WITNESS_KEY_FILE} is not a 32-byte scalar"))?;
        let sk = p256::ecdsa::SigningKey::from_bytes(&scalar.into())
            .map_err(|_| format!("{WITNESS_KEY_FILE} is not a valid P-256 private key"))?;
        Ok(WitnessKey { sk })
    }

    fn to_hex_line(&self) -> String {
        let mut s = to_hex(&self.sk.to_bytes());
        s.push('\n');
        s
    }
}

impl Signer for WitnessKey {
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let sig: p256::ecdsa::Signature = self.sk.sign_prehash(digest).expect("sign");
        // Low-S always: the core rejects high-S signatures, and a witness emitting one would
        // produce a cosignature that fails on every device.
        sig.normalize_s().unwrap_or(sig).to_bytes().into()
    }

    fn public_key(&self) -> PubKeyBytes {
        self.sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("33-byte compressed key")
    }
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

struct State {
    key: WitnessKey,
    log: WitnessLog,
}

/// Load a witness and re-verify every byte of its state.
///
/// Nothing is trusted for having been on disk: `WitnessLog::resume` re-checks the issuer's
/// signature on every retained checkpoint, re-compares them against each other, and re-checks
/// this witness's signature on every cosignature it thinks it issued. State that was tampered
/// with is refused here rather than believed and then signed on top of.
fn load(dir: &Path) -> Result<State, String> {
    let key_path = dir.join(WITNESS_KEY_FILE);
    check_key_permissions(&key_path);
    let key = WitnessKey::from_hex_text(&read_required(dir, WITNESS_KEY_FILE)?)?;

    let issuer = parse_pubkey(&read_required(dir, ISSUER_KEY_FILE)?, ISSUER_KEY_FILE)?;
    let recorded = parse_pubkey(&read_required(dir, WITNESS_PUB_FILE)?, WITNESS_PUB_FILE)?;
    if recorded != key.public_key() {
        // A swapped key file with the old public key left behind. Caught here because every
        // cosignature this tool then emitted would be attributed to a key the issuer's mirror
        // does not list, and the failure would surface as "the witness stopped working" on
        // somebody else's phone.
        return Err(format!(
            "{WITNESS_PUB_FILE} holds {} but {WITNESS_KEY_FILE} is the key for {} — \
             this state directory has been mixed up",
            to_hex(&recorded),
            to_hex(&key.public_key())
        ));
    }

    let seen = parse_seen(&read_optional(dir, SEEN_FILE)?)?;
    let issued = parse_issued(&read_optional(dir, ISSUED_FILE)?)?;
    let log = WitnessLog::resume(key.public_key(), issuer, &seen, &issued, &P256Verifier)
        .map_err(|r| format!("this witness's own state does not verify: {}", describe(&r)))?;

    Ok(State { key, log })
}

/// Persist the log. **Order matters.**
///
/// `seen.hex` is written before `issued.hex`. A crash between the two leaves a checkpoint
/// with no cosignature, which is a legal state (a witness may hold a head it never attested
/// to) and simply re-cosigns next time. The other order would leave a cosignature naming a
/// checkpoint the witness no longer holds, which `resume` refuses outright — the witness
/// would be bricked until somebody repaired the file by hand.
fn save(dir: &Path, log: &WitnessLog) -> Result<(), String> {
    write_atomic(
        dir,
        SEEN_FILE,
        &render_lines(log.seen().map(|cp| cp.encode())),
    )?;
    write_atomic(
        dir,
        ISSUED_FILE,
        &render_lines(log.issued().map(|c| c.encode())),
    )
}

fn describe(refusal: &WitnessRefusal) -> String {
    match refusal {
        WitnessRefusal::Unusable(e) => format!("{e:?}"),
        WitnessRefusal::Equivocation(p) => format!(
            "the issuer equivocated ({:?})",
            p.kind()
                .map(|k| format!("{k:?}"))
                .unwrap_or_else(|| "unclassified".to_string())
        ),
    }
}

/// Said by `init` and `status`, because a witness whose custody nobody thought about is a
/// witness that adds a signature and no assurance.
fn custody_warning(dir: &Path) {
    note!(
        "
Custody, plainly:
  * {key} is a private key in plaintext on this disk. Anything that can read this file can
    sign as this witness. It is 0600, which stops other local users and nothing else.
  * A real witness must be a genuinely DIFFERENT PARTY from the issuer — the market
    association, the co-op, the union. A second process run by whoever runs the issuer is a
    costume: it will produce valid cosignatures and protect nobody, because the party that
    would lie is the party holding both keys.
  * While this witness and the issuer are the same person, this is a MECHANISM TEST and not
    an assurance. It proves the loop works. It proves nothing about the issuer.
  * {seen}/{issued} are this witness's memory. Back them up, and never restore an older copy
    over a newer one: rolling them back is exactly how a witness gets talked into cosigning a
    second head at a position it already attested to.",
        key = dir.join(WITNESS_KEY_FILE).display(),
        seen = SEEN_FILE,
        issued = ISSUED_FILE,
    );
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(dir: &Path, args: &[String]) -> Result<ExitCode, String> {
    let issuer_hex = flag_value(args, "--issuer").ok_or(
        "init needs --issuer <hex>: the public key of the issuer whose history this witness \
         watches. Get it from the mirror's issuer.pub.",
    )?;
    let issuer = parse_pubkey(&issuer_hex, "--issuer")?;

    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;

    let key = WitnessKey::generate()?;
    // Written first, with create_new: if a witness already lives here this fails before
    // anything else is touched, so `init` can never overwrite a key that has signed things.
    write_secret(&dir.join(WITNESS_KEY_FILE), &key.to_hex_line())?;

    let pubkey = key.public_key();
    write_atomic(dir, WITNESS_PUB_FILE, &format!("{}\n", to_hex(&pubkey)))?;
    write_atomic(dir, ISSUER_KEY_FILE, &format!("{}\n", to_hex(&issuer)))?;
    write_atomic(dir, SEEN_FILE, "")?;
    write_atomic(dir, ISSUED_FILE, "")?;

    note!("Initialised a witness at {}.", dir.display());
    note!("  witness  {}", to_hex(&pubkey));
    note!("  watching {}", to_hex(&issuer));
    note!(
        "
Hand that witness key to the issuer, who adds it to the mirror:
  igopay-mirror init <mirror> --issuer <issuer-hex> --witness {}
(or appends it to the mirror's witnesses.txt). Until the issuer lists it, cosignatures from
this witness verify fine and count for nothing — a reader has no reason to trust a key
nobody published.",
        to_hex(&pubkey)
    );
    custody_warning(dir);
    Ok(ExitCode::SUCCESS)
}

// ---------------------------------------------------------------------------
// pubkey / status / verify
// ---------------------------------------------------------------------------

fn cmd_pubkey(dir: &Path) -> Result<ExitCode, String> {
    let s = load(dir)?;
    out!("{}", to_hex(s.log.witness_pubkey()));
    Ok(ExitCode::SUCCESS)
}

fn cmd_status(dir: &Path) -> Result<ExitCode, String> {
    let s = load(dir)?;
    note!("witness   {}", to_hex(s.log.witness_pubkey()));
    note!("watching  {}", to_hex(s.log.issuer_pubkey()));
    note!("cosigned  {} position(s)", s.log.len());
    match s.log.head() {
        None => note!("head      (nothing offered yet)"),
        Some(head) => note!(
            "head      seq {} epoch {} digest {}",
            head.seq,
            head.epoch,
            to_hex(&head.body_digest())
        ),
    }
    report_gaps(&s.log);
    custody_warning(dir);
    Ok(ExitCode::SUCCESS)
}

fn cmd_verify(dir: &Path) -> Result<ExitCode, String> {
    // `load` IS the verification: it re-checks every signature and every comparison.
    let s = load(dir)?;
    note!("witness   {}", to_hex(s.log.witness_pubkey()));
    note!("watching  {}", to_hex(s.log.issuer_pubkey()));
    note!(
        "state     {} checkpoint(s) held, {} cosignature(s) issued",
        s.log.seen().count(),
        s.log.len()
    );
    report_gaps(&s.log);
    note!(
        "
OK — every checkpoint here is signed by that issuer, every link that could be checked checks,
no two of them contradict each other, and every cosignature is this witness's own work.

What this does NOT tell you: whether the issuer showed somebody else a different head at a
position this witness never saw. Nothing on one machine can tell you that. Compare against the
public mirror (`igopay-mirror verify`), and use `check` on any head a payee brings you."
    );
    Ok(ExitCode::SUCCESS)
}

/// Positions this witness holds a checkpoint for but never attested to, and positions it has
/// simply never seen.
///
/// Worth surfacing: a gap is not an error, but a witness with many gaps is one the issuer is
/// not actually asking, and its cosignatures then cover less than an operator assumes.
fn report_gaps(log: &WitnessLog) {
    let seqs: Vec<u64> = log.seen().map(|c| c.seq).collect();
    let unattested: Vec<String> = seqs
        .iter()
        .filter(|s| log.cosignature_at(**s).is_none())
        .map(|s| s.to_string())
        .collect();
    if !unattested.is_empty() {
        note!("          held but not cosigned: {}", unattested.join(", "));
    }
    if let (Some(&first), Some(&last)) = (seqs.first(), seqs.last()) {
        let expected = last - first + 1;
        if (seqs.len() as u64) < expected {
            note!(
                "          {} position(s) between {first} and {last} were never offered to this witness",
                expected - seqs.len() as u64
            );
        }
    }
}

// ---------------------------------------------------------------------------
// cosign — the one verb that matters
// ---------------------------------------------------------------------------

fn cmd_cosign(dir: &Path, args: &[String]) -> Result<ExitCode, String> {
    let arg = args.get(2).ok_or("cosign needs <checkpoint-hex|file>")?;
    let cp = read_checkpoint_arg(arg)?;
    let mut s = load(dir)?;

    match s.log.cosign(&cp, now(), &s.key, &P256Verifier) {
        Ok(cosig) => {
            // Persisted BEFORE the artefact is printed. A cosignature released by a witness
            // that then forgot it is the one outcome worth engineering against: the next
            // request at that position would look new, and it would get a second signature.
            save(dir, &s.log)?;
            note!(
                "Cosigned position {} (epoch {}), head digest {}.",
                cp.seq,
                cp.epoch,
                to_hex(&cp.body_digest())
            );
            out!("{}", to_hex(&cosig.encode()));
            note!(
                "
Give that to the issuer to publish:
  igopay-mirror attest <mirror> <the-hex-above>
It must also travel WITH the checkpoint to devices, or an offline payee has nothing to check."
            );
            Ok(ExitCode::SUCCESS)
        }
        Err(WitnessRefusal::Equivocation(proof)) => {
            report_conflict(&proof, &cp);
            out!("{}", to_hex(&proof.encode()));
            Ok(ExitCode::from(EXIT_CONFLICT))
        }
        Err(WitnessRefusal::Unusable(e)) => Err(format!(
            "refused: {e:?} — this witness will not cosign it. Nothing was written."
        )),
    }
}

// ---------------------------------------------------------------------------
// check — the offline dispute path
// ---------------------------------------------------------------------------

fn cmd_check(dir: &Path, args: &[String]) -> Result<ExitCode, String> {
    let arg = args.get(2).ok_or("check needs <checkpoint-hex|file>")?;
    let cp = read_checkpoint_arg(arg)?;
    let s = load(dir)?;

    // Conflict first. A head that convicts the issuer must never be reported as a head this
    // witness merely does not recognise.
    if let Some(proof) = s.log.conflicting(&cp) {
        report_conflict(&proof, &cp);
        out!("{}", to_hex(&proof.encode()));
        return Ok(ExitCode::from(EXIT_CONFLICT));
    }

    match s.log.checkpoint_at(cp.seq) {
        Some(mine) if mine.body_digest() == cp.body_digest() => {
            note!(
                "Recognised: position {} epoch {} is the head this witness attested to.",
                cp.seq,
                cp.epoch
            );
            match s.log.cosignature_at(cp.seq) {
                Some(cosig) => {
                    note!("Its cosignature follows on stdout; attach it to the checkpoint.");
                    out!("{}", to_hex(&cosig.encode()));
                    Ok(ExitCode::SUCCESS)
                }
                None => {
                    note!("This witness holds that checkpoint but never cosigned it.");
                    Ok(ExitCode::from(EXIT_UNKNOWN))
                }
            }
        }
        // Unreachable in practice — a different body at a held position is equivocation and
        // was caught above — but reported rather than asserted, because a panic here would be
        // a witness crashing on the one input it exists to handle.
        Some(_) => Err(
            "this witness holds a different checkpoint at that position, yet no \
                        proof could be derived; report this state directory as a bug"
                .to_string(),
        ),
        None => {
            note!(
                "No opinion: this witness was never offered position {}. That is not a clean \
                 bill of health — it means nobody asked.",
                cp.seq
            );
            Ok(ExitCode::from(EXIT_UNKNOWN))
        }
    }
}

fn report_conflict(proof: &EquivocationProof, offered: &Checkpoint) {
    let (a, b) = (&proof.a, &proof.b);
    note!(
        "CONFLICT at position {} — the issuer signed two different histories.",
        offered.seq
    );
    note!(
        "  kind      {}",
        proof
            .kind()
            .map(|k| format!("{k:?}"))
            .unwrap_or_else(|| "unclassified".to_string())
    );
    note!(
        "  seq {} epoch {} digest {}",
        a.seq,
        a.epoch,
        to_hex(&a.body_digest())
    );
    note!(
        "  seq {} epoch {} digest {}",
        b.seq,
        b.epoch,
        to_hex(&b.body_digest())
    );
    note!(
        "
Nothing was written and no cosignature was issued. The proof is on stdout: two of the
ISSUER'S OWN signatures, verifiable by anyone with the issuer's public key and nobody's word
for anything. Publish it. A refusal nobody hears is just a missing signature, and a missing
signature looks like an outage."
    );
}
