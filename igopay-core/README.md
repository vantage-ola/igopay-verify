# igopay-core

The offline payment-promise protocol as a **pure Rust library** — Phase 1 of
`research/07-build-plan.md`. No UI, no network, no platform dependencies. This is
where protocol correctness is won before any app is built.

Rationale for a Rust core (not Kotlin) and for ECDSA P-256 (not Ed25519) is in
`research/09-phase0-results.md` §6 (decision D5).

## What it does

| Module | Responsibility |
|---|---|
| `codec` | Canonical CBOR (RFC 8949 §4.2.1 subset), hand-rolled so byte-for-byte determinism is an audited property. Decoders reject non-canonical input. |
| `crypto` | ECDSA P-256, raw `r‖s` (64 B). Verification only. **High-S signatures are rejected** to close the malleability fork-proof forgery vector. Signing is the `Signer` trait — never in the core. |
| `types` | `Certificate`, `Promise`, `ForkProof`, `PaymentRequest` + strict encoders/decoders. Certificate is embedded in the promise (D2) and carries an issuer-signed `[not_before, not_after]` validity window. |
| `build` | The payer/issuer side: `build_certificate` and `PromiseBuilder` turn fields + a platform `Signer` into signed artefacts that verify by construction, tracking `seq`/`prev_hash` so a promise chain links correctly (B2). |
| `clock` | Uptime-anchored `Clock` trait: `now = last_trusted_utc + (uptime_now − anchor)`. Never the wall clock (Phase 0 §4.2). `SKEW_TOLERANCE_SECS = 5`. |
| `blocklist` | Compact block list (B13): Bloom filter + exact recent-fork set, plus the issuer-signed `SignedBlockList` wire format devices install. Monotonic `epoch` blocks rollback replay; expiry marks a list stale, never void. `no_std` (`BTreeSet`, no hasher, integer-only filter sizing). |
| `checkpoint` | Checkpoints (B7): the issuer's own hash-chained history of what it published, so it cannot tell two devices two different stories. `Checkpoint`, the three equivocation rules, `EquivocationProof`, and the device-side `CheckpointTracker` (bounded, like `ledger`). |
| `witness` | Witness cosignatures (B7): a second party attests to **one head per log position**, and the signature travels with the checkpoint — so an offline payee can check the anchor at the counter instead of trusting that an auditor will look later. |
| `qr` | D1 QR transport codec: unpadded uppercase RFC 4648 base32 (fits QR alphanumeric mode). Strict decoder rejects out-of-alphabet chars, impossible lengths, and non-canonical trailing bits. |
| `hex` | Hex and the "one artefact per line" text container the published files use. Transport plumbing, verifying nothing — it lives here because the parties reading and writing those files are deliberately *different parties*, and a witness should not have to link the issuer's crate to decode a line. |
| `ledger` | The payee's per-payer state: `ChainHead` + a **bounded** set of retained promises, so a same-`seq` different-body promise yields a fork proof on the spot. Retention is capped (Android Go `ram.low`), evicting the lowest `seq`. |
| `verify` | The full offline check list (`07` §2), **certificate validity window**, **hash-chain continuity (B2)**, **B10 slot-grant alignment**, and fork detection. |

## Certificate validity window (offline self-revocation)

The certificate carries an issuer-signed `[not_before, not_after]` UTC-second
window, so it is short-lived by construction. `verify_promise` checks it against the
anchored clock **before** cap/slot/chain checks:

- **not-yet-valid** — `now < not_before` → `CertNotYetValid`.
- **expired** — `now > not_after` → `CertExpired`. This is how a superseded or
  revoked payer key stops being accepted with **no online revocation lookup** (B9):
  the payee simply refuses a cert whose window has closed.
- **inverted** — `not_after < not_before` is a malformed grant → `CertWindowInverted`,
  rejected even though issuer-signed.
- **grant ⊆ validity** — the slot grant must fall inside the validity window
  (`grant.from ≥ not_before` and `grant.to ≤ not_after`), else `GrantOutsideValidity`.
  A coherent issuer never grants slots for a period the certificate is not valid
  over; checked against the signed window, so it holds regardless of the clock.

Both bounds are inclusive (`now == not_before` and `now == not_after` are valid).

## QR transport (D1)

Raw QR *byte* mode mojibakes on budget-phone scanners (Phase 0 §1), so promise
bytes never go into a QR directly. `to_qr_payload` / `from_qr_payload` encode them as
**unpadded uppercase RFC 4648 base32** — every character is a QR alphanumeric
symbol, and base32 in alphanumeric mode is denser on the wire than byte mode once
mode overhead is counted. The decoder is strict, mirroring the CBOR codec's
discipline: out-of-alphabet characters, impossible lengths, and non-zero trailing
bits are all rejected so a payload has exactly one valid encoding. The exact base32
string for the golden promise is pinned in `tests/vectors/golden.json`.

## Slot grants as a namespace (B10)

The grant is a pre-allocated set of slots spaced `granularity_secs` apart from
`grant.from`, not a range of free seconds. `verify_promise` enforces:

- **in-window** — `grant.from ≤ slot ≤ grant.to`, else `SlotOutsideGrant`.
- **on-boundary** — `(slot − grant.from) % granularity_secs == 0`, else
  `SlotMisaligned`. The spacing is what makes the grant double as a rate limit.
- **not future** — `slot ≤ now + SKEW_TOLERANCE_SECS`, else `SlotInFuture`.

## Fork proofs are portable evidence (B8)

`ForkProof` serializes to a canonical 2-element array (`encode`/`from_bytes`) so it
can be handed to the issuer or another payee, decoded byte-for-byte, and
independently re-verified with `verify_fork_proof`.

## Checkpoints: the same discipline, applied to the issuer (B7)

The protocol already makes a payer unable to lie — two promises at one `seq` are a
fork proof signed by their own hardware. The issuer had no equivalent. It signs the
block list, so nothing stopped it publishing one list to some devices and a
*different* list at the same `epoch` to others, or quietly rewriting last week's.

`checkpoint` closes that by turning B2 on the issuer. Every publication gets one
signed `Checkpoint { seq, epoch, list_digest, prev_hash, issued_at }`: `seq` is its
position in the issuer's log, `epoch`/`list_digest` are the list it commits to, and
`prev_hash` links it to the entry before. The payer is chained and forks by reusing a
`seq`; the issuer is now chained and equivocates by reusing one.

**Position and epoch are separate counters, deliberately.** The log owns `seq` and
appends consecutively, so `seq` can never gain a gap — which is what makes rule E2
below sound. `epoch` comes from outside, and a service that increments its publication
counter then fails mid-publish leaves a legitimate gap; a rule that treated gaps as
fraud would convict an honest issuer for crashing.

Two validly-signed checkpoints are an `EquivocationProof` if they break any of:

- **E1 `DuplicatePosition`** — same `seq`, different body. The direct analogue of a
  payer reusing a seq.
- **E2 `BrokenLink`** — adjacent positions whose hash link does not hold. The entry at
  `seq n+1` names the *unique* entry at `n`, so one naming anything else says two
  entries exist at `n`. This is what catches a rewrite of last week's history.
- **E3 `EpochNotAdvancing`** — a later position whose epoch did not advance. This
  catches "two lists at one epoch" even when the issuer is careful enough to give the
  second one its own position, and it catches an epoch rollback.

The reason is always *derived* from the pair, never carried in the artefact: a claimed
reason is worth nothing, and re-deriving it costs two comparisons.

### Binding a list to its checkpoint

Without this the chain is decorative. `install_checkpointed_list` is the device-side
install path: verify the checkpoint, verify that it commits to *this exact list*
(`verify_list_commitment`), then apply every block-list rule unchanged. Requiring the
commitment is what forces a divergent list to arrive with a divergent checkpoint — and
a divergent checkpoint is the proof. (Certificate Transparency does the same by
refusing a certificate that arrives without an SCT.)

### `CheckpointTracker` — bounded, like the ledger

The device keeps a bounded window of checkpoints, evicting the lowest `seq`. The head
alone would catch an issuer handing two devices different *current* lists; a window is
what lets two devices compare at a position both still remember, and it is the only
reason E2 is reachable in practice. `offer` returns one of: `FirstSeen`, `Advanced`,
`AdvancedWithGap { skipped }`, `Duplicate`, `Superseded`, or
`Equivocation(EquivocationProof)`.

Two of those encode real decisions:

- **A gap installs.** Block lists are whole snapshots, so a device offline for a month
  installs the newest and never sees the intermediate ones. Refusing would leave it on
  an older list that blocks *fewer* cheaters — the same "never fail open on
  revocation" reasoning as list staleness. Missing links can be fetched later and
  checked with `verify_chain_link`.
- **An equivocating checkpoint is not adopted.** The device keeps the story it already
  had and hands the proof up. Adopting the second story would destroy the evidence for
  the first, which is exactly what the equivocating issuer wants.

### What this does not buy

A chain makes equivocation **provable once two views are compared**; it does not make
anyone compare them. Two devices that never meet can be told different histories
indefinitely, which is why publishing the head somewhere public is the other half of
B7 (`igopay-issuer`'s `anchor` seam) — and why `CheckpointTracker::position_of` exists,
so a device can check an anchored digest against the history it was told.

A checkpoint also says nothing about whether the list's *contents* are right. An issuer
that omits a real cheat publishes one consistent history that happens to be wrong.
Checkpoints constrain the issuer to **one** story; they cannot make that story true.

## Witness cosignatures: the anchor a payee can check offline (B7)

Publishing the head where strangers can read it has a hole for this protocol
specifically: reading a public log needs connectivity **at the moment of the check**, and
the premise here is a payee with none. An anchor a trader cannot read protects auditors,
not traders.

So a second party — a witness — signs the checkpoint under one rule: **at most one head
per log position, ever**. Its signature rides *with* the checkpoint, over the same carried
transport as the block list (B12), so the payee verifies two signatures and needs no
network to do it. The guarantee changes shape:

- without a witness — "the issuer cannot lie to two devices without being caught, *if*
  those two devices ever meet";
- with a witness — "the issuer cannot show me a head that nobody else was shown".

That is the difference between detection later and refusal now, at the counter.

`WitnessLog` is the witness's side, and it is a `CheckpointTracker` retaining everything
plus a signing step — so the "one head per position" rule is enforced by the same
comparison devices run, a refusal comes with a portable `EquivocationProof` rather than an
opinion, and a witness will not cosign across a broken chain link. Being `no_std` with
signing behind the `Signer` trait, a witness can be an association officer's **phone**
rather than a server.

Its state must be persisted, and *restoring* it is part of the protocol rather than a
convenience: a witness that forgets a position can be talked into cosigning a second head
there, so a witness whose memory ended with its process would be one whose rule could be
defeated by asking it to reboot. `WitnessLog::resume` reads back `seen()` and `issued()`
and **re-verifies every byte** — the issuer's signature on each retained checkpoint, the
comparisons between them, this witness's own signature on each cosignature — so state
tampered with on disk is refused at load rather than believed and signed on top of. It
fails exactly the way `cosign` does, handing back an `EquivocationProof` if the stored
history contradicts itself. Two rules that are easy to miss: a cosignature naming a
checkpoint no longer present is **refused**, not dropped (a witness holding a statement it
cannot defend is worse than one holding nothing), and where a position has two, the
earliest is kept, so a restored witness agrees with whatever was distributed first.

Three decisions in the artefact are worth knowing:

- **The cosignature is domain-separated** (`SHA-256(COSIGN_DOMAIN ‖ body)`). The issuer
  signs a checkpoint's body digest; if a witness signed that same digest, the two would be
  signatures over an *identical message*, so any key that ever served both roles would make
  every cosignature a valid issuer signature — a witness could mint history. Key hygiene
  should be good practice, not the thing holding the roof up.
- **The cosignature names the issuer**, not just the digest. A checkpoint's body carries no
  issuer identity, so two issuers publishing the same list at the same position produce
  byte-identical checkpoint bodies (trivially so for an empty list at genesis). Without the
  issuer field, an attestation would fit both.
- **Cosignatures are additive, never identity.** A checkpoint's identity stays its own body
  digest, so two devices holding the same checkpoint with different cosignature sets — one
  collected before a witness replied, one after — hold the same checkpoint, and collecting
  one more signature never looks like a second story.

Coverage is **reported, not enforced** (`WitnessCoverage`). What thin attestation should
cost a payer is a limits question, and a device that refused every unwitnessed head would
also refuse honest ones during a witness outage — then run on an older block list, failing
open on revocation to guard against equivocation. Wrong trade.

## Payee request flow

`PaymentRequest` is the unsigned QR the payer scans **first**: it carries the payee
key, amount/currency, and a fresh payee-generated nonce (the core is `no_std` and has
no RNG, so the platform supplies the nonce). `verify_promise_for_request` then checks
a returned promise against that request — it threads the request's `payee_pubkey` and
`nonce` into the full offline check list so the app can't verify against the wrong key
or a stale nonce, and additionally requires the promise's amount and currency to
equal what was requested (`AmountMismatch` / `CurrencyMismatch`).

## The payee ledger: turning rejection into evidence

`verify_promise` is stateless, but a payee must hold state between payments. Keeping
only the head digest lets a payee *reject* a double spend; it does not let them
*prove* one, because the earlier promise is gone. `PayeeLedger` therefore keeps, per
payer:

- the `ChainHead` fed back as `known_head` on the next verification (B2), and
- a **bounded** set of retained promises, so `check_for_fork` can build a real
  `ForkProof` the moment a same-`seq` different-body promise arrives.

Retention is capped per payer because the target device is Android Go with `ram.low`
(`research/09` §3); at the cap the **lowest `seq`** is evicted. That is a deliberate,
tested tradeoff: a fork against an evicted `seq` is no longer provable by that payee,
while recent seqs — the ones a double spend is most likely to hit — stay covered.

**What a single payee cannot do (B9):** a payer who spends `seq = 12` with payee A and
a different `seq = 12` with payee B is invisible to each alone. That fork only surfaces
when the two promises are combined (at the issuer, or via a shared block list). An
accepted promise is also "pending, not settled" — the ledger is not a settlement record.

## Hash-chain continuity (B2)

`verify_promise` links each promise to the payer's stored `ChainHead`
`(seq, body_digest)`:

- **seq must strictly advance** — a promise never reuses or falls below an accepted
  seq (`SeqDiscontinuity`).
- **immediate successor is `prev_hash`-linked** — when `seq == head.seq + 1`, the
  promise's `prev_hash` must equal the stored head's body digest, or it is rejected
  (`PrevHashMismatch`). A payer cannot skip or rewrite history without forking.
- **gaps are not asserted** — when seq jumps by more than one (promises made to
  payees we never saw), the intervening link can't be checked offline, so `prev_hash`
  is not asserted; the gap is still visible via exposure disclosure.

On success `Accepted::new_head` returns the head to persist for the next promise.

## `no_std`

The crate is `#![no_std]` + `alloc` only, so it links cleanly into the mobile FFI
layer and constrained builds. Tests link `std` as usual.

## The consensus-critical invariants

1. **Canonical encoding** — same logical value ⇒ same bytes, always.
2. **Low-S only** — a malleated `(r, n−s)` copy of an honest promise must never be
   accepted, or it could masquerade as a fork proof.
3. **Promise identity = SHA-256 of the signed body** — the basis of fork detection.

## Private keys never enter the core

Signing is a platform trait (`crypto::Signer`) implemented over Android Keystore or
the iOS Secure Enclave. The core only ever *verifies*. The test suite ships a
deterministic in-process `TestSigner` (in `tests/common/`) solely to build
reproducible adversarial vectors — it is not a production signer.

The `build` module is the blessed way to *produce* signed artefacts: it takes a
`&dyn Signer` (the platform's hardware wrapper) and computes the exact canonical body
digest the verifier recomputes, so `build_certificate` output and `PromiseBuilder`
output verify by construction. `PromiseBuilder` owns the `seq`/`prev_hash` state, so
a payer cannot accidentally reuse a seq or break the hash chain — the link is
covered end-to-end in `tests/builder.rs`.

## Build & test

The sandbox cannot write to `~/.cargo`, so use a workspace-local cargo home:

```bash
cd igopay-core
CARGO_HOME="$PWD/.cargo-home" CARGO_TARGET_DIR="$PWD/target" cargo test
```

## Test coverage (Phase 1 exit criterion)

`tests/adversarial.rs` — 31 vectors: wrong payee, replayed nonce, over-cap,
slot-before-grant, **slot-misaligned**, future slot, slot-within-skew, seq replay,
prev_hash chain break, linked successor accepted, seq-gap not asserted, blocked
payer, forged issuer/payer signatures, high-S malleability, truncated/trailing
bytes, roundtrip identity, fork detection (genuine double spend,
duplicate-is-not-a-fork, different-payer, fabricated-proof-rejected,
**fork-proof roundtrip**), and **certificate validity** (in-window,
inclusive boundaries, not-yet-valid, expired, inverted window,
grant-outside-validity on both ends, expiry-before-other-checks ordering,
windowed-cert roundtrip).

`tests/fork_property.rs` — the exit criterion. A **small grid** (120 pairs) runs by
default to keep `cargo test` fast; the **full 3,240-pair sweep** is `#[ignore]`d and run
in CI via `cargo test --test fork_property -- --ignored`. Either way: **any** two
same-`seq` promises with distinct bodies yield a fork proof that independently
verifies; identical bodies never do.

`tests/builder.rs` — the payer/issuer side: built certificates and promises verify by
construction, a two-promise chain links via `prev_hash`, a promise from a *separate*
genesis builder is rejected (`PrevHashMismatch`), and `sign_promise_body` matches the
builder byte-for-byte.

`tests/request_flow.rs` — the payee request flow: `PaymentRequest` roundtrip, honest
promise accepts, and the request-specific rejections (wrong amount — which the cert cap
alone would let through — wrong currency, stale nonce, wrong payee).

`tests/ledger.rs` — the payee ledger: head-driven chain continuity across three linked
payments, a broken link rejected without advancing state, **a double spend producing a
fork proof that independently verifies**, duplicates not reported as forks, bounded
retention evicting the lowest `seq` (including the honest consequence that an evicted
fork is unprovable), payers tracked independently, and `forget_payer`.

`tests/wire_size.rs` — regression guard that the encoded promise (~320 B, now
including the certificate validity window) stays under the 400 B QR budget
(Phase 0 §1).

`tests/blocklist.rs` — 29 vectors for the block list and its signed wire format,
mostly adversarial. A block list is an instruction to refuse someone's money, so the
attacks worth testing are the ones against an *honest* payer: a forged or malleated
issuer signature, tampering with the filter bits or the exact set, a **replayed older
epoch** (which would un-block a payer caught since) and an **equal** epoch, and an
inverted validity window. Two design decisions are pinned here: an **expired list still
installs and still blocks** — otherwise waiting for expiry would be a way to get
un-blocked, and refusing it would leave the device on an older list that blocks fewer
cheaters — and filter geometry is **integer-only**, because a float-derived probe count
could differ between an x86 server and an ARM phone while the geometry is part of the
wire format. Six further cases cover malformed lists that must produce errors rather
than panic a phone: zero `num_bits` (a divide by zero when deriving positions), zero
probes, a short bit buffer (an out-of-bounds index), an oversized filter or probe count
(memory and CPU exhaustion), and too many, unsorted or duplicated exact entries.
Publication from the issuer's blocked set is covered in `igopay-issuer/tests/publish.rs`.

`tests/checkpoint.rs` — 43 vectors for checkpoints (B7). The block-list tests prove a
device refuses a forged or replayed list; these prove the issuer cannot tell two devices
two different stories. Most of the file is pairs of artefacts — one honest, one from the
other story — including all three equivocation rules (two lists at one position, two
lists at one epoch at *different* positions, and a rewritten history caught by a broken
link), plus an epoch rollback. Equally important are the pairs that must **not** convict:
an honest chain compared against itself in both directions, a re-signed identical
checkpoint (identity is the body, not the signature), two entries far enough apart that
nothing links them, and a **malleated copy** of an honest checkpoint, which would
otherwise let anyone manufacture evidence against an issuer that did nothing. The
commitment path is covered from both sides — a checkpointed list installs and still
blocks, a *different* list at the same epoch is refused, and the rollback guard still
fires — and the tracker's own decisions are pinned: a gap installs rather than leaving
the device on an older list, an equivocating checkpoint is never adopted, evidence takes
precedence over every other verdict, and a rewrite below the retained window is
**undetectable by the phone** (asserted so the limit cannot rot into a surprise).

`tests/witness.rs` — 32 vectors for cosignatures. The end-to-end one is
`a_split_view_cannot_get_two_heads_witnessed`: the issuer signs two epoch-7 stories, both
install, and only one can carry the witness's signature — so the device offered the other
can tell at the counter, with no network. The rest are mostly the ways this could quietly
fail: a cosignature must not double as an issuer signature (asserted with one key wearing
both hats, which is the hygiene failure we refuse to depend on), must not transfer to
**another issuer's** identical-bodied checkpoint, must not be liftable onto a different
position, and must not change a checkpoint's identity — that last one matters most, because
if it did, collecting one more attestation would read as equivocation. Also: canonical and
deduplicated cosignature sets (a repeated witness cannot inflate coverage), a malleated or
tampered cosignature from a *trusted* witness stopping the install rather than counting as
zero, coverage counting trusted witnesses while ignoring strangers, an idempotent witness,
one that refuses to sign what the issuer did not sign or across a broken link or under the
wrong key, and an unwitnessed list still installing.

Nine of those cover **surviving a restart**, because the rule is "ever" and `ever` has to
outlive a power cut: a resumed witness hands back the cosignature it already issued rather
than minting a second one, still refuses a second head at a position it cosigned before the
restart, still turns a head a payee brings it into a proof, and refuses to load a state file
that was tampered with, that contradicts itself, that carries another witness's work,
another issuer's attestation, or a cosignature whose checkpoint has gone missing.

`tests/golden_vectors.rs` + `tests/vectors/golden.json` — pinned canonical bytes for
a certificate, two forking promises, their fork proof, and the promise's **base32 QR
transport string**, produced by the documented deterministic seeds. These are the
**cross-platform contract**: any conforming implementation (or the mobile FFI on a
real device) must reproduce the exact bytes, the QR string, the digests, and the
accepting verdict. A wire-format change fails these loudly rather than silently
breaking interop. `igopay-ffi` re-checks the same vectors *through the FFI boundary*.

## Cross-platform binding

The UniFFI binding layer lives in the sibling `igopay-ffi` crate: a thin std shell
that exposes a byte-in / verdict-out surface (`verify_promise_bytes`,
`detect_fork_bytes`, `verify_fork_proof_bytes`) and generates Kotlin + Swift
bindings, so Android and iOS run this exact core. See `../igopay-ffi/README.md`.

## Still needs on-device hardware (next in Phase 1)

- A two-platform FFI run (Android emulator `.so` + iOS simulator static lib) feeding
  both the same vector and asserting equal verdicts — belongs in CI with the NDK and
  Xcode toolchain (`research/09-phase0-results.md` §6). The host-side determinism
  proof is already in `igopay-ffi/tests/ffi_smoke.rs`.
