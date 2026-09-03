//! `igopay-mirror` — publish and audit the issuer's checkpoint log as a public text mirror.
//!
//! B7's publication half. The issuer's history goes into a public git repository as one hex
//! line per publication, so anyone can clone it, re-verify every signature and link, and
//! compare the head against what their own phone was told. A rewrite then shows up as a
//! changed line in a public diff instead of a story only one device ever heard.
//!
//! **This tool implements nothing.** The format lives in `igopay_issuer::mirror` and every
//! verification rule in `igopay_core`; here there is only file I/O and printing. That is the
//! point: `verify` has to be trustworthy, and it cannot be if it is a second implementation
//! that might disagree with the first.
//!
//! It also deliberately does not touch git or OpenTimestamps. It prints the commands to run.
//! A human staying in the loop for each publication is not a weakness here — a signing key
//! that no unattended job can use is a signing key that unattended malware cannot use
//! either — and it keeps this binary free of any opinion about how you publish.
//!
//! ```text
//! igopay-mirror verify <dir>                    audit a mirror; what a stranger runs
//! igopay-mirror head <dir>                      print the head digest (the stamp target)
//! igopay-mirror init <dir> --issuer <hex> [--witness <hex>]...
//! igopay-mirror append <dir> <checkpoint-hex|file>
//! igopay-mirror attest <dir> <cosignature-hex|file>
//! igopay-mirror demo <dir> [publications]       throwaway keys, for exercising the loop
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use igopay_core::checkpoint::Checkpoint;
use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::witness::Cosignature;
use igopay_core::P256Verifier;
use igopay_issuer::mirror::{
    check_head, coverage, from_hex, parse_checkpoints, parse_cosignatures, parse_head, parse_key,
    parse_keys, render_checkpoints, render_cosignatures, render_head, render_key, render_witnesses,
    to_hex, CHECKPOINTS_FILE, COSIGNATURES_FILE, HEAD_FILE, ISSUER_KEY_FILE, WITNESSES_FILE,
};
use igopay_issuer::CheckpointLog;

const README_FILE: &str = "README.md";
const DEMO_MARKER: &str = "THIS-IS-A-DEMO";

/// Print a line, treating a closed pipe as a normal end rather than a panic.
///
/// An auditor will pipe `verify` into `head` or `grep`, and the default `println!` panics with
/// `Broken pipe` when they do. A tool whose job is to make people comfortable inspecting
/// things should not crash when they inspect it in the obvious way.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write;
        let mut lock = std::io::stdout().lock();
        if writeln!(lock, $($arg)*).is_err() {
            std::process::exit(0);
        }
    }};
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(cmd) = args.first().map(String::as_str) else {
        usage();
        return ExitCode::from(2);
    };

    let result = match cmd {
        "verify" => need_dir(&args).and_then(|d| cmd_verify(&d)),
        "head" => need_dir(&args).and_then(|d| cmd_head(&d)),
        "init" => need_dir(&args).and_then(|d| cmd_init(&d, &args)),
        "append" => need_dir(&args).and_then(|d| cmd_append(&d, &args)),
        "attest" => need_dir(&args).and_then(|d| cmd_attest(&d, &args)),
        "demo" => need_dir(&args).and_then(|d| cmd_demo(&d, &args)),
        "-h" | "--help" | "help" => {
            usage();
            return ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command `{other}`")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(1)
        }
    }
}

fn usage() {
    eprintln!(
        "igopay-mirror — publish and audit the issuer's checkpoint log (B7)

USAGE
  igopay-mirror verify <dir>
  igopay-mirror head   <dir>
  igopay-mirror init   <dir> --issuer <hex> [--witness <hex>]...
  igopay-mirror append <dir> <checkpoint-hex|file>
  igopay-mirror attest <dir> <cosignature-hex|file>
  igopay-mirror demo   <dir> [publications]

Every command reads the issuer key from <dir>/{ISSUER_KEY_FILE} and re-verifies the whole
log; nothing is trusted because it is already in the file."
    );
}

fn need_dir(args: &[String]) -> Result<PathBuf, String> {
    args.get(1)
        .map(PathBuf::from)
        .ok_or_else(|| "missing <dir>".to_string())
}

/// All values given as `--flag value`.
fn flag_values(args: &[String], flag: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            if let Some(v) = args.get(i + 1) {
                out.push(v.clone());
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

/// Read an artefact given either inline hex or a path to a file containing it.
///
/// Both, because the two call sites are different: a service pipes hex, and a human who
/// received a cosignature over a messaging app saves it to a file.
fn read_hex_arg(arg: &str) -> Result<Vec<u8>, String> {
    if let Some(bytes) = from_hex(arg) {
        return Ok(bytes);
    }
    let text = fs::read_to_string(arg)
        .map_err(|e| format!("`{arg}` is neither hex nor a readable file: {e}"))?;
    from_hex(text.trim()).ok_or_else(|| format!("`{arg}` does not contain hex"))
}

fn read_optional(dir: &Path, name: &str) -> Result<String, String> {
    let path = dir.join(name);
    match fs::read_to_string(&path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("reading {}: {e}", path.display())),
    }
}

fn read_required(dir: &Path, name: &str) -> Result<String, String> {
    let path = dir.join(name);
    fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn write_file(dir: &Path, name: &str, contents: &str) -> Result<(), String> {
    let path = dir.join(name);
    fs::write(&path, contents).map_err(|e| format!("writing {}: {e}", path.display()))
}

/// Everything a mirror holds, verified.
struct LoadedMirror {
    issuer: PubKeyBytes,
    witnesses: Vec<PubKeyBytes>,
    log: CheckpointLog,
    cosignatures: Vec<Cosignature>,
}

/// Load and fully verify a mirror: every signature, every link, the head, the keys.
///
/// This is the audit, and it is the same code path `append` runs before writing — so the tool
/// cannot extend a log it would refuse to publish.
fn load(dir: &Path) -> Result<LoadedMirror, String> {
    let issuer = parse_key(&read_required(dir, ISSUER_KEY_FILE)?)
        .ok_or_else(|| format!("{ISSUER_KEY_FILE} does not hold a 33-byte SEC1 public key"))?;
    let witnesses = parse_keys(&read_optional(dir, WITNESSES_FILE)?)
        .map_err(|e| format!("{WITNESSES_FILE}: {e}"))?;

    let entries = parse_checkpoints(&read_optional(dir, CHECKPOINTS_FILE)?)
        .map_err(|e| format!("{CHECKPOINTS_FILE}: {e}"))?;
    let head =
        parse_head(&read_optional(dir, HEAD_FILE)?).map_err(|e| format!("{HEAD_FILE}: {e}"))?;
    check_head(&entries, head).map_err(|e| format!("{HEAD_FILE}: {e}"))?;

    let log = CheckpointLog::resume(issuer, entries, &P256Verifier)
        .map_err(|e| format!("the log does not verify: {e:?}"))?;

    let cosignatures = parse_cosignatures(&read_optional(dir, COSIGNATURES_FILE)?)
        .map_err(|e| format!("{COSIGNATURES_FILE}: {e}"))?;

    Ok(LoadedMirror {
        issuer,
        witnesses,
        log,
        cosignatures,
    })
}

// ---------------------------------------------------------------------------
// verify
// ---------------------------------------------------------------------------

fn cmd_verify(dir: &Path) -> Result<(), String> {
    let m = load(dir)?;
    out!("mirror   {}", dir.display());
    out!("issuer   {}", to_hex(&m.issuer));
    out!("entries  {}", m.log.len());

    if dir.join(DEMO_MARKER).exists() {
        out!("\n!! {DEMO_MARKER} is present: these are throwaway keys, not an issuer.\n");
    }

    match m.log.head() {
        None => println!("head     (empty log — nothing published yet)"),
        Some(head) => {
            out!(
                "head     seq {} epoch {} digest {}",
                head.seq,
                head.epoch,
                to_hex(&head.body_digest())
            );
        }
    }

    let (per_position, unknown) = coverage(
        m.log.entries(),
        &m.cosignatures,
        &m.issuer,
        &m.witnesses,
        &P256Verifier,
    );
    out!(
        "witness  {} trusted key(s), {} cosignature(s) in file, {} not credited",
        m.witnesses.len(),
        m.cosignatures.len(),
        unknown
    );
    if !m.witnesses.is_empty() && !per_position.is_empty() {
        let attested = per_position.iter().filter(|p| p.witnesses > 0).count();
        out!(
            "         {attested}/{} position(s) attested",
            per_position.len()
        );
        let gaps: Vec<String> = per_position
            .iter()
            .filter(|p| p.witnesses == 0)
            .map(|p| p.seq.to_string())
            .collect();
        if !gaps.is_empty() {
            out!("         unattested positions: {}", gaps.join(", "));
        }
    }

    out!("\nOK — every signature and every link verifies.");
    out!(
        "Nothing here proves the LIST CONTENTS are right, and nothing here is a timestamp:\n\
         check {HEAD_FILE} against its external stamp separately, and check this head against\n\
         what your own device holds."
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// head
// ---------------------------------------------------------------------------

fn cmd_head(dir: &Path) -> Result<(), String> {
    let m = load(dir)?;
    match m.log.head() {
        Some(head) => {
            out!("{}", to_hex(&head.body_digest()));
            Ok(())
        }
        None => Err("the log is empty; there is no head to stamp".to_string()),
    }
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

fn cmd_init(dir: &Path, args: &[String]) -> Result<(), String> {
    let issuer_hex = flag_values(args, "--issuer")
        .into_iter()
        .next()
        .ok_or("init needs --issuer <hex>")?;
    let issuer = parse_key(&issuer_hex).ok_or("--issuer is not a 33-byte SEC1 public key")?;
    let witnesses: Vec<PubKeyBytes> = flag_values(args, "--witness")
        .iter()
        .map(|w| parse_key(w).ok_or_else(|| format!("--witness `{w}` is not a public key")))
        .collect::<Result<_, _>>()?;

    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    if dir.join(CHECKPOINTS_FILE).exists() {
        return Err(format!(
            "{} already exists — init would overwrite a published log",
            dir.join(CHECKPOINTS_FILE).display()
        ));
    }

    write_file(dir, ISSUER_KEY_FILE, &render_key(&issuer))?;
    write_file(dir, WITNESSES_FILE, &render_witnesses(&witnesses))?;
    write_file(dir, CHECKPOINTS_FILE, "")?;
    write_file(dir, COSIGNATURES_FILE, "")?;
    write_file(dir, HEAD_FILE, "")?;
    write_file(dir, README_FILE, &readme(&issuer, &witnesses))?;

    out!("Initialised an empty mirror at {}", dir.display());
    if witnesses.is_empty() {
        out!(
            "\nNo witnesses configured. {WITNESSES_FILE} is empty, which is an honest statement:\n\
             equivocation stays provable once two views are compared, and until a witness exists\n\
             nothing makes an offline payee able to refuse an unattested head."
        );
    }
    print_next_steps(dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// append
// ---------------------------------------------------------------------------

fn cmd_append(dir: &Path, args: &[String]) -> Result<(), String> {
    let arg = args.get(2).ok_or("append needs <checkpoint-hex|file>")?;
    let bytes = read_hex_arg(arg)?;
    let offered =
        Checkpoint::from_bytes(&bytes).map_err(|e| format!("not a canonical checkpoint: {e:?}"))?;

    let m = load(dir)?;

    // Rebuild the whole log with the new entry and let `resume` re-verify it end to end. That
    // is deliberately more work than checking one link: publication is exactly where the
    // paranoia is worth paying for, and it means a mirror that would fail `verify` can never
    // be written in the first place.
    let mut entries = m.log.entries().to_vec();
    entries.push(offered.clone());
    let extended = CheckpointLog::resume(m.issuer, entries, &P256Verifier)
        .map_err(|e| format!("this checkpoint does not extend the published log: {e:?}"))?;

    write_file(dir, CHECKPOINTS_FILE, &render_checkpoints(&extended))?;
    write_file(dir, HEAD_FILE, &render_head(&extended))?;

    out!(
        "Appended position {} (epoch {}).\nNew head digest: {}",
        offered.seq,
        offered.epoch,
        to_hex(&offered.body_digest())
    );
    print_next_steps(dir);
    Ok(())
}

// ---------------------------------------------------------------------------
// attest
// ---------------------------------------------------------------------------

fn cmd_attest(dir: &Path, args: &[String]) -> Result<(), String> {
    let arg = args.get(2).ok_or("attest needs <cosignature-hex|file>")?;
    let bytes = read_hex_arg(arg)?;
    let cosig = Cosignature::from_bytes(&bytes)
        .map_err(|e| format!("not a canonical cosignature: {e:?}"))?;

    let m = load(dir)?;

    if cosig.issuer_pubkey != m.issuer {
        return Err("this cosignature attests to a different issuer's history".to_string());
    }
    if !m.witnesses.contains(&cosig.witness_pubkey) {
        return Err(format!(
            "{} is not in {WITNESSES_FILE}; add the witness key first, deliberately",
            to_hex(&cosig.witness_pubkey)
        ));
    }
    let position = m
        .log
        .entries()
        .iter()
        .find(|cp| cp.body_digest() == cosig.checkpoint_digest)
        .map(|cp| cp.seq)
        .ok_or("this cosignature names a checkpoint that is not in the published log")?;
    cosig
        .verify(&P256Verifier)
        .map_err(|e| format!("the cosignature does not verify: {e:?}"))?;

    // Append-only: a late attestation is a new line, never an edit to a committed one.
    let mut all = m.cosignatures;
    if all.iter().any(|c| c == &cosig) {
        out!("Already published; nothing to do.");
        return Ok(());
    }
    all.push(cosig);
    write_file(dir, COSIGNATURES_FILE, &render_cosignatures(&all))?;

    out!("Recorded an attestation for position {position}.");
    print_next_steps(dir);
    Ok(())
}

fn print_next_steps(dir: &Path) {
    out!(
        "\nNext, by hand (this tool touches neither git nor OpenTimestamps):
  igopay-mirror verify {d}
  ots stamp {d}/{HEAD_FILE}
  git -C {d} add -A && git -C {d} commit -S -m \"publish\" && git -C {d} push",
        d = dir.display()
    );
}

// ---------------------------------------------------------------------------
// demo — throwaway keys, so the loop can be exercised before a service exists
// ---------------------------------------------------------------------------

/// A deterministic P-256 signer. **Demo only**: a real issuer's key lives in the service and
/// a real witness's key lives on the witness's own device, and neither ever appears here.
struct DemoSigner {
    sk: p256::ecdsa::SigningKey,
}

impl DemoSigner {
    fn from_seed(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1);
        DemoSigner {
            sk: p256::ecdsa::SigningKey::from_bytes(&bytes.into()).expect("valid scalar"),
        }
    }
}

impl Signer for DemoSigner {
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
            .expect("33-byte compressed key")
    }
}

fn cmd_demo(dir: &Path, args: &[String]) -> Result<(), String> {
    let n: u64 = match args.get(2) {
        Some(s) => s.parse().map_err(|_| "publications must be a number")?,
        None => 3,
    };

    let issuer = DemoSigner::from_seed(1);
    let witness = DemoSigner::from_seed(2);
    let registry = igopay_issuer::PromiseRegistry::new(issuer.public_key());
    let mut log = CheckpointLog::new(issuer.public_key());
    let mut witness_log = igopay_core::WitnessLog::new(witness.public_key(), issuer.public_key());
    let mut cosignatures = Vec::new();

    for epoch in 1..=n {
        let params = igopay_issuer::PublishParams::new(epoch, 1_700_000_000 + epoch * 3_600);
        let published =
            igopay_issuer::publish_with_checkpoint(&registry, &params, &issuer, &mut log)
                .map_err(|e| format!("publishing epoch {epoch}: {e:?}"))?;
        let cosig = witness_log
            .cosign(
                &published.checkpoint,
                1_700_000_060 + epoch * 3_600,
                &witness,
                &P256Verifier,
            )
            .map_err(|e| format!("cosigning epoch {epoch}: {e:?}"))?;
        cosignatures.push(cosig);
    }

    fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let witnesses = vec![witness.public_key()];
    write_file(dir, ISSUER_KEY_FILE, &render_key(&issuer.public_key()))?;
    write_file(dir, WITNESSES_FILE, &render_witnesses(&witnesses))?;
    write_file(dir, CHECKPOINTS_FILE, &render_checkpoints(&log))?;
    write_file(dir, COSIGNATURES_FILE, &render_cosignatures(&cosignatures))?;
    write_file(dir, HEAD_FILE, &render_head(&log))?;
    write_file(dir, README_FILE, &readme(&issuer.public_key(), &witnesses))?;
    write_file(
        dir,
        DEMO_MARKER,
        "The keys in this directory were generated from fixed seeds by `igopay-mirror demo`.\n\
         They are worth nothing. Never publish this as an issuer's transparency mirror.\n",
    )?;

    out!(
        "Wrote a DEMO mirror with {n} publication(s) to {}.\n\
         The issuer and witness keys came from fixed seeds and are worth nothing.\n",
        dir.display()
    );
    out!("Try:  igopay-mirror verify {}", dir.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// The mirror's own README, generated so it cannot drift from the tool.
// ---------------------------------------------------------------------------

fn readme(issuer: &PubKeyBytes, witnesses: &[PubKeyBytes]) -> String {
    let witness_block = if witnesses.is_empty() {
        "No witnesses are configured yet, and `witnesses.txt` is empty. That is an honest\nstatement rather than an omission: see \"What this does not prove\".\n".to_string()
    } else {
        let mut s = String::from("Trusted witness keys (also in `witnesses.txt`):\n\n");
        for w in witnesses {
            s.push_str(&format!("- `{}`\n", to_hex(w)));
        }
        s
    };

    format!(
        r#"# igopay transparency mirror

This is the **complete published history** of one igopay issuer's block lists, in a form
anyone can check. It exists so that the issuer cannot tell two devices two different stories
about who is blocked: every publication is committed to here, and a rewrite of history shows
up as a changed line in this repository's diff.

Issuer public key (also in `{ISSUER_KEY_FILE}`):

    {issuer_hex}

{witness_block}
## Files

| File | What it is |
|---|---|
| `{CHECKPOINTS_FILE}` | The log. One checkpoint per line, hex-encoded canonical CBOR; line *n* holds position *n*. **Append-only** — a publication is exactly one added line. |
| `{COSIGNATURES_FILE}` | Witness attestations, one per line, in arrival order. Separate from the log because a witness may reply long after publication, and appending a line must never mean editing one. |
| `{HEAD_FILE}` | The digest of the most recent checkpoint. This is the single value that gets timestamped externally. |
| `{ISSUER_KEY_FILE}` | The issuer's public key, so you need nothing from the issuer to verify this. |
| `{WITNESSES_FILE}` | Public keys of witnesses whose attestations are counted. |

## How to check it yourself

    git clone <this repo> && cd <this repo>
    igopay-mirror verify .

That re-derives every checkpoint digest, checks the issuer's signature on each one, checks
that each links to its predecessor, checks that `{HEAD_FILE}` names the last entry, and
verifies every witness cosignature. It trusts nothing in these files for being here.

To confirm the history is not being quietly rewritten *now*, two more things:

1. **Check the external timestamp** on `{HEAD_FILE}` (an OpenTimestamps receipt, if one is
   published alongside it). A timestamp proves a head existed by a certain time; it does not
   prove uniqueness, so it is a complement to the checks above, not a substitute.
2. **Compare against your own device.** If your wallet holds a checkpoint at some position and
   this log holds a *different* one at that position, those two signed artefacts together are
   proof of misbehaviour that anyone can verify — and they do not require anyone to be
   believed, including us.

Commit signatures: the `allowed_signers` file, if present, lets you verify this repository's
commits without trusting the hosting provider:

    git -c gpg.ssh.allowedSignersFile=allowed_signers log --show-signature

## What this does not prove

**That the block lists are correct.** A checkpoint commits to the *content* of a published
list. An issuer that leaves a genuine cheat off the list, or puts an innocent payer on it,
publishes one perfectly consistent history that happens to be wrong. Catching that needs the
fork proofs themselves, which any payee can verify independently.

**That anybody is watching.** These files make misbehaviour undeniable once two views are
compared. Someone has to compare them. If a witness key is listed above, attestations give an
*offline* payee a way to refuse an unattested head on the spot; without one, detection depends
on two devices eventually meeting.

**Payment data is not here, deliberately.** A checkpoint carries digests, an epoch and a
position — no payer keys, no amounts, nothing about anyone's payments. The block lists
themselves are not mirrored, because publishing them would mean publishing a permanent
world-readable list of blocked keys.
"#,
        issuer_hex = to_hex(issuer),
    )
}
