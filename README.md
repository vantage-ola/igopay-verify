# igopay-verify — check the transparency log yourself

The tools and libraries needed to **verify the igoPay issuer's published history**, and to **be
an independent witness to it**. Nothing here needs to be trusted: it checks signatures, and you
can read exactly how.

Published because the alternative is not transparency. A mirror whose verifier nobody can compile
is *inspectable*, not *verifiable*; and a witness is supposed to be an independent party, which
they cannot be if the software only we can build.

## The log this checks

    https://github.com/vantage-ola/igopay-transparency

Its commits are signed. That repository carries an `allowed_signers` file, but a file cannot
vouch for itself — so here is the anchor, obtained from somewhere other than the repository it
authorises:

| | |
|---|---|
| Principal | `vantageola4@gmail.com` |
| Key fingerprint | `SHA256:dL4wDYji3CVcld0gns3HbLAdFqTCfENEXbHOgUD9a50` |

Compare that against the mirror's `allowed_signers`:

    ssh-keygen -lf <(cut -d' ' -f2,3 allowed_signers)

## Verify the log

    git clone https://github.com/vantage-ola/igopay-transparency mirror
    cd tools/igopay-mirror && cargo build --release && cd -
    tools/igopay-mirror/target/release/igopay-mirror verify mirror

That re-derives every checkpoint digest, checks the issuer's signature on each one, checks that
each links to its predecessor, checks that `head.txt` names the last entry, and verifies every
witness cosignature. It trusts nothing in those files for being there.

## What the log is for

igoPay moves signed **payment promises** between phones with no network. A payer who spends the
same promise twice produces, from their own two signatures, a proof of it that any stranger's
phone can check — no server adjudicates. That leaves exactly one party unchecked: the issuer,
which signs the list of blocked payers. Nothing stopped it publishing one list to some devices
and a *different* list at the same epoch to others; every device would verify happily, because
everything it held agreed with everything else it held.

So the issuer is now chained too. Every publication gets a signed
`Checkpoint { seq, epoch, list_digest, prev_hash, issued_at }`, and two checkpoints that cannot
both belong to one honest log are an `EquivocationProof` — deliberately the same shape as a
payer's fork proof. Both are two signed artefacts that cannot both be honest, checkable by
anyone, adjudicated by nobody.

Three rules make the comparison total: two entries at one position, a broken link between
adjacent positions, or an epoch that fails to advance with position.

## Be a witness

The strongest version of this does not depend on anyone reading a log later. A **witness** — a
market association, a co-op, a motor-park union — signs each head under one rule:

> at most one head per log position, ever.

That cosignature travels *with* the checkpoint, so a payee **with no connectivity** verifies a
second signature at the counter. The guarantee changes from "the issuer cannot lie to two devices
without being caught, if those two devices ever meet" to "the issuer cannot show me a head that
nobody else was shown". Detection later becomes refusal now.

    cd tools/igopay-witness && cargo build --release && cd -
    tools/igopay-witness/target/release/igopay-witness init ./witness-state --issuer <issuer-hex>
    tools/igopay-witness/target/release/igopay-witness cosign ./witness-state <checkpoint-hex>

Read `tools/igopay-witness/src/main.rs` before you run it in earnest — particularly what it says
about key custody and about backing up its memory, because a witness that forgets a position can
be talked into cosigning a second head there, which is the exact failure it exists to prevent.

A witness run by whoever runs the issuer is a costume. If you are considering being one, that
independence is the whole contribution.

## What is here

| Crate | What it is |
|---|---|
| `igopay-core/` | The protocol, `#![no_std]`: canonical CBOR, ECDSA P-256 with high-S rejected, the payer hash chain and fork proofs, uptime-anchored slot grants, the block list, the payee ledger, checkpoints and witness cosignatures. **No private keys, no I/O, no clock of its own.** |
| `igopay-issuer/` | The published mirror format, the issuer's append-only checkpoint log, and cross-payee fork detection. No network, no database. |
| `tools/igopay-mirror/` | The CLI an auditor runs. Pure I/O — every rule it enforces lives in the crates above, so `verify` is not a second implementation that could disagree with the one phones run. |
| `tools/igopay-witness/` | The CLI a witness runs. Deliberately does **not** link `igopay-issuer`: a witness carrying the issuer's code would make the separation this rests on a naming convention rather than a fact. |
| `tools/igopay-publish/` | The CLI the issuer runs. Included not because you need it, but because it is where you can check that **a payer can only be blocked with a fork proof** — two of their own signatures over conflicting promises. It also cannot read the signing key: custody is an external command, so the same tool works with a Secure Enclave, a StrongBox-backed app, a PKCS#11 token or a cloud KMS. |

Each crate has its own README with the reasoning, and the tests are written as adversarial pairs —
one honest artefact, one from the other story — including the pairs that must **not** convict.

## What is not here

**The mobile boundary (`igopay-ffi`).** Not needed to verify a log or to witness from a laptop.
A witness on a *phone* does need it, and that is a real gap rather than an oversight.

**The design notes, threat model and market analysis.** None of it is needed to check a signature.

**Any payment data, ever.** A checkpoint carries a position, an epoch and two digests. The block
lists themselves are deliberately not mirrored either: they contain blocked payers' public keys,
and publishing them would mean publishing a permanent world-readable blacklist.

### Citations you cannot follow from here

The code and crate READMEs cite `research/…` and `igopay-ffi` in places. Those are real files in
the private repository, left in place rather than edited out — this projection is byte-identical to
its source, and a copy that quietly rewrote its own comments is a copy you would be right not to
trust. For reference:

| Cited as | What it is |
|---|---|
| `research/05-threat-model.md` | The adversaries and the attack catalogue, including A9 — the issuer itself, which is why this log exists |
| `research/06-design-igopay.md` | The design: promises, hash chains, fork proofs as reputation |
| `research/07-build-plan.md` | The mechanisms borrowed and from where. B7 is this log, B13 the block list, B2 the payer chain |
| `research/09-phase0-results.md` | Measured results: QR capacity, clock drift, attestation, and why the curve is P-256 |
| `igopay-ffi` | The UniFFI boundary carrying `igopay-core` to Android and iOS |

Nothing in the verification path depends on reading any of them. They explain *why*; the code and
its tests establish *what*.

## Provenance, and its limits

This repository is generated from a private one — see `PROVENANCE` for the exact source commit
(`9593cb8e8b36`). You cannot check that stamp from here, and you do not have to: the
verification does not trust this repository or its authors. It checks the issuer's signatures.

## Honest limits

**A verified log is not a correct one.** A checkpoint commits to a list's *content*. An issuer
that leaves a genuine cheat off the list, or puts an innocent payer on it, publishes one perfectly
consistent history that happens to be wrong.

**Somebody still has to look.** These files make misbehaviour undeniable once two views are
compared. A witness cosignature is what makes a *payee* able to refuse on the spot; without one,
detection waits for two devices to meet.

**Nothing here has been used in production.** The issuer's publication key exists and is held in
hardware, but no block list has been published, no witness has been appointed, and the log is
empty and says so. Until a witness independent of the issuer holds a key, a cosignature proves
only that the issuer cosigned its own history — which is why the tools call that a mechanism test
rather than an assurance.

**The issuer's key is not yet anchored outside its own mirror.** `igopay-mirror verify` reads the
issuer's public key from the mirror it is checking, so it confirms that history is consistent
*under the key that mirror declares*. That is enough to catch an issuer telling two stories to two
devices, because devices receive the key when they are enrolled and do not take it from here. It is
not enough for a stranger auditing from scratch: two mirrors under two different keys would each
verify. The fix is the same one used for the commit-signing key above — publish the publication key
somewhere other than the mirror — and it will land with the first publication.

## Licence

MIT or Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`.
