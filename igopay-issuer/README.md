# igopay-issuer

The issuer's **domain logic**, as a pure Rust library — Phase 2 of
`research/07-build-plan.md`. Like `igopay-core`, this crate has **no network, no
database, no HTTP**: it is the decision logic a service wraps, so it can be tested
exhaustively before any transport exists.

## Why an issuer exists at all

Everything about a promise is verifiable offline by the payee, with one exception the
protocol cannot close locally (B9): a payer who spends `seq = 12` with payee A and a
*different* `seq = 12` with payee B is invisible to each of them alone.
`igopay_core::PayeeLedger` catches a double spend only against promises that **same**
payee retained. The fork surfaces when the two promises are finally brought together.

That is this crate's job. The issuer is **not** a trusted authority over payments — it is
a **rendezvous point for evidence**. It cannot invent a fork, because a fork proof is two
promises signed by the payer's own hardware key. It can only notice one.

## The core is a dependency, not a spec

`igopay-core` is imported directly rather than reimplemented server-side. If the issuer
had its own verification code, the issuer and a payee could disagree about whether a fork
proof is valid — the one disagreement this protocol cannot survive. One audited
implementation, every party.

| Module | Responsibility |
|---|---|
| `registry` | Dedupe on `(payer_pubkey, seq)`; the fork-proof engine. Where the cross-payee gap is closed. |
| `publish` | Block-list publication policy (B13). The wire format lives in `igopay_core::blocklist`. |
| `checkpoint` | The append-only log of what has been published (B7): assigns positions, links and signs each entry, and refuses a non-advancing epoch. The artefact and its rules live in `igopay_core::checkpoint`. |
| `anchor` | The `AnchorSink` seam — publishing the log's head where a stranger can read it. `NoOpAnchor` and `ManualAnchor` only. |
| `settlement` | The `SettlementAdapter` seam (`08` §6 decision 2). `NoOpSettlement` and `ManualSettlement` only. |

## The registry cannot frame anyone

Two properties make its output safe to act on:

1. **Nothing is registered unless it verifies.** `submit` checks the issuer signature on
   the embedded certificate *against this issuer's key*, checks the payer signature on
   the promise body, and rejects high-S (malleable) signatures. A payee cannot poison the
   registry with a forged promise to get a payer blocked — and on refusal **nothing is
   recorded at all**.
2. **A fork proof is re-verifiable by anyone.** What the registry emits is the same
   artefact `igopay_core::verify_fork_proof` validates, so a payer, another payee, or an
   auditor can confirm it without trusting the issuer. The issuer's say-so is not part of
   the evidence.

`submit_fork_proof` (for a proof a payee's own ledger caught) is **re-verified from
scratch** for the same reason: "this payer double spent" is an accusation with
consequences.

### The keying *is* the design

`(payer_pubkey, seq)` is what makes a double spend a **collision** rather than two
unrelated rows. Storage here is an in-memory `BTreeMap` because the crate is
persistence-free, but any real schema must preserve that unique index — it is the whole
mechanism, not an implementation detail.

## Pending is not complete

`SettlementStatus` has no state that could be mistaken for finality, and
`NoOpSettlement` **can never** return `Settled`. This is load-bearing: `04` use case 1
requires a merchant's receipt to say *pending*, never complete, until money has actually
moved. An adapter that optimistically reported success would reintroduce exactly the
false-finality risk the offline design exists to avoid.

`NipSettlement` and `SuiSettlement` are later implementations of the same trait — the
seam is what keeps the rail and jurisdiction question open (`08` §5–6).

## Publishing a block list

`publish_block_list` compresses everything the registry has blocked into one signed
artefact small enough to reach a device that is rarely online. The policy lives here; the
format, the install rules and every rejection live in `igopay_core::blocklist`, because
publisher and phone must agree on filter geometry and hash positions byte-for-byte.

Three properties do the real work, and each is a defence against a specific attack:

1. **It is signed.** A block list is an instruction to refuse someone's money. An unsigned
   one would let anybody censor any payer at will — denial of service against honest
   users, not against cheats.
2. **It cannot be rolled back.** `epoch` must be **strictly** greater than the epoch a
   device already holds. Without that, replaying yesterday's list would silently un-block
   a payer caught since. Equal epochs are refused too, so two lists cannot be swapped at
   the same version.
3. **Expiry never fails open.** `not_after` makes a list *stale*, not void: entries stay in
   force and staleness instead means the *absence* of an entry is less trustworthy, so a
   payee should tighten its offline limits. If expiry dropped entries, waiting would be a
   way to get un-blocked — which is also why `verify_and_open` takes no clock at all, and
   why an already-expired list still installs (refusing it would leave the device on an
   older list that blocks *fewer* cheaters).

Every blocked payer goes in the Bloom filter **and** the most recent ones additionally go
in the exact set. The redundancy costs a few bits and buys a simpler invariant: the filter
alone is a complete answer, so ageing out of the exact window is never a moment where
somebody stops being blocked.

The caller owns one piece of state the registry cannot infer: the **epoch counter**. It
must be persisted and monotonic. Reusing an epoch produces a list every up-to-date device
will reject.

## Checkpointing what was published (B7)

Signing the block list was never enough. The issuer could publish one list to some devices
and a *different* list at the same `epoch` to others, and every device would verify happily,
because everything it holds agrees with everything else it holds. Nothing anywhere compared
the two.

`CheckpointLog` fixes the publisher's side. Each publication appends one signed
`Checkpoint` carrying its position in the log, the epoch and body digest of the list, and a
hash link to the entry before it. `publish_with_checkpoint` is the entry point a service
should call, because the two halves must not be separable in practice: a list published
without a checkpoint leaves every device that installs it holding no evidence of what it
was given, and a checkpoint written for a list signed by a different key would produce a
commitment no device can satisfy.

**The log is a guard rail before it is evidence.** The first thing `append_for_list` does is
refuse an epoch that does not advance. Before this, two racing publisher processes could
each ship an epoch-9 list and nothing would notice — the two devices that installed them
would simply hold different views of who is blocked, forever. Now that is a refused append,
at the one place every publication passes through. So: same-epoch equivocation is
impossible **by accident**, and provable when deliberate.

Positions are assigned here rather than supplied, so a caller cannot create a gap, a
duplicate position or a broken link even by mistake. Epoch gaps *are* allowed — a service
that burns a counter value on a failed publish is honest, and the two counters are separate
precisely so that stays true.

Three operations exist for the aftermath:

- `since(seq)` — what a device that has been offline needs to close its gap. A checkpoint is
  about 180 bytes, so a device a hundred publications behind catches up in under 20 KB.
- `audit` — re-verify every signature and every link. What an auditor runs, and what an
  issuer should run on itself; `resume` runs it on startup, because a restart is the moment
  a rewrite would be easiest to slip in.
- `conflicting` — the dispute desk. A payee turns up with "this is what I was told", and the
  answer is two of the issuer's own signatures rather than the issuer's word.

## Anchoring the head (the other half of B7)

A chain makes the issuer's history self-consistent or provably not. It does not make anyone
look. `AnchorSink` is the seam for putting the head somewhere a stranger can read it —
OpenTimestamps, a CT-style witness, a chain object, or something as simple as a public post.
`08` §4.2 goes further and proposes replacing the issuer's log with on-chain version
conflicts, which would remove the issuer as a trusted party rather than merely watching it;
that substitution is the reason this is a seam and not a hard-coded call.

`NoOpAnchor` **cannot** report anchored, exactly as `NoOpSettlement` cannot report settled.
The failure being designed out is the same: a dashboard reading "anchored" while nothing was
ever published would be worse than no anchor at all, because the whole point is to make
quiet divergence loud. `Pending` is not a success state either — an unconfirmed timestamp is
not something a third party can read — and `ManualAnchor::confirm` requires a non-empty
external reference.

`audit_anchored_head` is the reconciliation anyone can run: read the digest from wherever it
was posted, ask the issuer for its log, compare. `Behind` is the normal steady state
(anchoring lags publication). `NotInLog` is the alarm — and, importantly, not by itself the
proof: promoting it needs the signed checkpoint behind that digest, which is why the anchor
stores the digest and somebody keeps the checkpoint.

### `WitnessAnchor` — the one that helps a trader rather than an auditor

Every anchor that publishes a digest shares one weakness on this protocol: reading it needs
connectivity at the moment of the check, and the premise here is a payee with none.
`WitnessAnchor` collects **cosignatures** instead (`igopay_core::witness`), which travel with
the checkpoint and are verifiable offline. The service loop:

1. `publish_with_checkpoint` → a list and a checkpoint;
2. `submit` the checkpoint → `Pending`;
3. send it to each witness and collect what comes back;
4. `record_cosignature` each one — at the threshold the status becomes `Anchored`;
5. `witnessed` → the artefact that ships alongside the list.

A cosignature is verified before it is kept, and refused unless it comes from a trusted
witness, names *this* issuer, and names a head this sink actually submitted. An issuer that
kept unverified cosignatures would ship artefacts every device rejects — the same class of
self-inflicted outage `append_for_list` guards against by checking the signing key. With no
witnesses configured nothing ever reaches `Anchored`, which is the honest outcome rather than
a special case.

And a witness that **refuses** hands back an equivocation proof instead of a signature. That
is not an error to retry around: it means the issuer just asked to have two heads attested at
one position, and the response is to stop publishing and find out which process produced the
second one.

### The public mirror

`mirror` renders the log as plain text for a public git repository: one hex line per
publication, position *n* on line *n*. The point of text is the diff — **a publication is
exactly one added line**, so an append is distinguishable from a rewrite by anyone reading the
repository's history, including someone who understands none of the cryptography. A compact
binary blob would hide that completely. Measured cost: a checkpoint is 148 bytes, so ~297
characters a line, and hourly publication for a year is about 3 MB of text.

Cosignatures live in a **separate** file. They arrive after publication — a witness may reply
seconds later or the next morning — so keeping them inline would mean editing a line that had
already been committed, which destroys the property the format exists for. In their own file a
late attestation is a new line.

Two things are deliberately absent. **The block lists themselves**: a checkpoint carries
digests, an epoch and a position, while a list carries the public keys of blocked payers, so
mirroring lists would publish a permanent world-readable blacklist. The digests are enough —
anyone can check that the list they hold is the one that was published. And **any cryptography
in the parser**: the format is a container, `CheckpointLog::resume` re-verifies every signature
and link, and a parser that verified signatures would tempt a caller into thinking parsing was
enough.

`tools/igopay-mirror` is the I/O shell around this — `verify`, `head`, `init`, `append`,
`attest`, and a `demo` that mints throwaway keys so the whole loop can be exercised before an
issuer service exists. It implements nothing itself, and touches neither git nor
OpenTimestamps: it prints the commands to run, which keeps a human in the loop and this crate
free of any opinion about how you publish.

The witness on the other side of `attest` is `tools/igopay-witness`, a separate binary that
holds a witness key and cosigns one head per position. It links `igopay-core` and **not this
crate** — a witness carrying the issuer's code would make the separation the mechanism rests on
a naming convention rather than a fact, which is why the hex and line-container primitives this
module uses live in `igopay_core::hex` and are re-exported here.

## Build & test

The sandbox cannot write to `~/.cargo`, so use a workspace-local cargo home:

```bash
cd igopay-issuer
CARGO_HOME="$PWD/.cargo-home" CARGO_TARGET_DIR="$PWD/target" cargo test
```

## Test coverage

`tests/registration.rs` — 33 vectors. The headline is
**`a_genuine_attestation_over_a_different_key_is_refused`**: a real, in-date chain that
roots to Google, attests to hardware, and belongs to another device admits nobody, because
the attested key is compared against the key being certified. Without that one comparison
a scraped attestation certifies a *software* key, and every other check here is hygiene.
Paired with `the_same_attestation_over_its_own_key_registers`, so the check is about the
binding rather than about rejecting anything unusual.

The other load-bearing vector is
**`raising_attestation_from_tee_to_strongbox_does_not_change_the_cap`** — D4 as an
executable claim rather than a paragraph. `TieringInputs` has no attestation field, so the
only way to attempt attestation-scaled caps is to register twice with different hardware
and compare.

Plus: software attestation refused and StrongBox admitted on the same gate; challenges
single-use, expiring, minimum-length, non-zero, non-reissuable, and **burnt even by a
failed attempt** (grinding); an attestation echoing another session's challenge refused;
KYC, clean history and a guarantor each raising the cap while history cannot climb past the
KYC ceiling; absurd history saturating instead of overflowing; a fork on record refusing
outright rather than merely capping to zero; verified boot required by default and waivable
deliberately; `RefusingVerifier` admitting nobody; expiry and root failures carried through
with their own reasons intact; and the issued certificate verifying under the issuer's own
key before it is returned.

`tests/registry.rs` — 14 vectors. The headline is
**`cross_payee_double_spend_is_caught_by_the_issuer`**: two payees each accept a promise
at the same `seq`, neither can prove a fork locally, and the issuer's second submission
produces a proof that independently verifies. Plus: exposure on first submission,
idempotent resubmission (including a wire round-trip), fork proof surviving
serialization, different-seq and different-payer both correctly *not* forks, a forged
payer signature refused with nothing recorded, a **malleated high-S** promise refused,
a foreign issuer's certificate refused, a payee-submitted proof re-verified then
accepted, a **fabricated** proof rejected blocking nobody, a hand-made duplicate pair
rejected, blocked-payer submissions still registering, and seq-ordered digests.

`tests/settlement.rs` — 7 vectors, mostly negative: `NoOpSettlement` never reports
settled and distinguishes pending from never-seen; `ManualSettlement` queues
idempotently, requires an operator plus a rail reference to settle, treats failure as
terminal, refuses to mark an unknown promise, and both adapters are interchangeable
through the trait object.

`tests/publish.rs` — 12 vectors covering the issuer's side of the seam: every blocked
payer reaches the published list, a payer who never forked does not, the most recently
blocked get the exact treatment while older ones stay in the filter, exact entries are in
the filter as well, an empty registry publishes a valid list that blocks nobody, a list
survives the wire, successive epochs install in order and a replay of the older one is
refused, a payee-submitted fork proof also lands in the list, re-blocking does not move a
payer in the recency order, the filter floor applies to small lists, an oversized exact
request is clamped to what a device accepts, and a rival issuer's list is refused.

The install-side rules are proved in `igopay-core/tests/blocklist.rs` — 29 vectors, mostly
adversarial: forged and malleated signatures, tampering with the filter bits or the exact
set, replayed and equal epochs, an inverted validity window, an expired list that must
still install and still block, and six malformed-list cases that must produce errors
rather than panic a phone (zero `num_bits`, zero probes, a short bit buffer, an oversized
filter, too many probes, too many or unsorted or duplicated exact entries).

`tests/checkpoint.rs` — 13 vectors for the log. The headline is
**`two_publisher_processes_that_bypass_the_log_are_caught`**: the issuer really does run two
publishers to get two different epoch-7 lists, both are perfectly signed, each installs on
its own device — and when the two devices meet, one walks away holding a proof that anyone
can re-check. Plus the guard rail from both directions (a reused epoch and an older epoch
refused *without extending the log*), an epoch gap accepted while positions stay contiguous,
the wrong signing key refused before anything is distributed, a lagging device catching up
through `since`, the dispute desk answering from `conflicting`, `resume` refusing a tampered
chain / a dropped entry / a rival's history, an empty log auditing cleanly, and the
commitment being over the list **body** so a re-signed identical list still matches while one
extra blocked payer does not.

`tests/anchor.rs` — 17 vectors, mostly negative, because the failure mode here is a
dashboard that lies. `NoOpAnchor` can never report anchored and still distinguishes
unanchored from never-submitted; `ManualAnchor` refuses a confirmation with an empty
reference or for a head it never saw, is idempotent on resubmission and never rolls a
confirmed head back to pending; `Pending` is asserted **not** to count as publicly visible;
and `audit_anchored_head` covers all four answers, including `NotInLog` from a genuinely
divergent second log and the promotion from that alarm to a real proof. The `WitnessAnchor`
vectors add the threshold (one of two witnesses is not anchored, two is), the collected
artefact verifying on a device and surviving the wire, resubmission not discarding
cosignatures, and four ways a cosignature is refused — untrusted witness, tampered
signature, a head never submitted, and one attesting to another issuer's history.

`tests/mirror.rs` — 15 vectors for the publication format. The headline property is
`an_append_is_exactly_one_added_line`, since that is the whole reason the mirror is text. The
rest are the files a human or a broken job could produce and a reader must refuse: a dropped
line (reported with its position), a reordered log, a hand-edited or truncated entry, a head
that names a history other than the one in the file, and a truncated key. One vector pins the
division of labour — a tampered but still well-formed line **parses** and then dies at
`resume`, because the container format deliberately does no cryptography. Coverage is
computed from the mirror alone, counting a witness once even if its attestation appears twice
and crediting nothing for a bad signature, a stranger's key, or a checkpoint not in the log.

The end-to-end loop is covered in `tools/igopay-mirror/tests/loop.rs` — 7 vectors driving the
real binary: a demo mirror that verifies and declares itself a demo, `verify` refusing each
kind of bad mirror, `append` + `attest` composing into a publication, `append` refusing
anything `verify` would refuse (and leaving the mirror untouched when it does), `init`
refusing to clobber a published log, and usage errors that are usage errors rather than
crashes.

## Not yet built (and why)

**A production attestation verifier.** Registration and tiering are built (see below), but
the only `AttestationVerifier` in-tree is `RefusingVerifier`, which admits nobody. That is
the correct default — an issuer that forgets to wire the gate should register no devices,
not every device — and wiring the real one means driving the checks
`tools/verify_attestation.py` already performs against Google's pinned roots and status
list. Deliberately not a second X.509 implementation inside this crate: two gates that
admit different devices is worse than one gate.

**Block-list distribution.** Publication is done; *getting* a signed list to a device that
is rarely online is a transport problem and not solved here. The saving grace is that the
list grows with the number of **cheaters**, not the number of users.

**Reaching the phone.** Done: `verify_block_list` and `check_payer_against_block_list` are
exposed through `igopay-ffi`, and `verify_promise_bytes` takes the signed list directly so
the check cannot be skipped. The open question — re-verify per query, or verify once and
trust app storage — was settled by measurement (`igopay-core/tests/cost_probe.rs`): a
re-verify costs 0.5x-1.4x a single promise verification, so the trust assumption was not
worth taking. The **on-device** figure is still unmeasured.

**A live anchor.** The seam, the log, the evidence and the witness mechanism are built, and
the loop has been run end to end — publish, cosign, attest, `verify`, `ots stamp` — against a
demo mirror on one laptop, with a real second witness key held by `tools/igopay-witness` and a
181-byte cosignature this crate's `attest` path accepted. Nothing is published for real yet and
no witness is appointed, and `NoOpAnchor` says so rather than pretending. What remains is
operational rather than technical, and it is two decisions:

- **an issuer key, and its custody.** The tooling and format are built (`mirror`,
  `tools/igopay-mirror`), and a public repository holding one line per checkpoint plus an
  OpenTimestamps receipt on each head is the cheap baseline: readers need no account, anyone can
  clone it and re-run `resume` + `audit`, and the timestamp removes the host as the trusted
  timekeeper. What is missing is the key to publish under. It is the highest-value secret in the
  system — it signs every block list and every checkpoint — so it cannot live on a phone, and
  the custody answer, not the code, is what gates a real mirror. Because checkpoints chain,
  anchoring the head transitively covers everything before it, so the mirror can run far less
  often than publication (`Behind` is the expected steady state).
- **who the witness is.** The natural candidate is the party B14 already treats as the moat:
  the market association, co-op or motor-park union. It is a real second party — not a second
  server run by whoever runs the issuer, which is a costume — and it is the group a split view
  would be used against, so its incentive points the right way. Being `no_std`, `WitnessLog`
  can run on an officer's phone. While the witness is the same person as the issuer, the loop
  above is a **mechanism test and not an assurance**; `tools/igopay-witness` prints that on
  every `init` and `status` so the numbers cannot imply otherwise.

The gap until then is precise: equivocation is provable the moment two views meet, a witnessed
head is refusable on the spot, and with neither in place only devices that happen to compare
(a carried bundle, a dispute, two traders in one row) produce evidence.

Note `08` §4.2 proposes replacing the issuer's log with on-chain version conflicts, which
would remove the issuer as a trusted party entirely rather than merely watching it. The
`AnchorSink` seam exists so that substitution stays possible; it would also still want the
witness cosignature, because a chain lookup is another thing an offline payee cannot do.

### Known cleanup

`tests/common/mod.rs` duplicates a deterministic test signer that also exists in
`igopay-core/tests/common/` and `igopay-ffi/tests/`. Consolidating all three behind an
optional `test-util` feature on `igopay-core` is worthwhile and deliberately not bundled
into this change.
