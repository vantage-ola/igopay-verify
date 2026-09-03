//! Witness cosignatures (B7): the half of anchoring an **offline** payee can actually
//! check.
//!
//! [`crate::checkpoint`] makes issuer equivocation *provable once two views are compared*.
//! Nothing in it makes the comparison happen. The usual answer — publish the head
//! somewhere public — has a hole for this protocol specifically: reading a public log
//! needs connectivity **at the moment of the check**, and the whole premise here is a payee
//! with no connectivity. An anchor a trader cannot read is an anchor that protects
//! auditors, not traders.
//!
//! A cosignature closes that. A second party — a witness — signs the checkpoint under one
//! rule: **at most one head per log position, ever**. The signature travels *with* the
//! checkpoint, over the same carried-by-hand transport as the block list (B12), so a payee
//! verifies two signatures instead of one and needs no network to do it. The guarantee
//! changes shape:
//!
//! * without a witness — "the issuer cannot lie to two devices without being caught, if
//!   those two devices ever meet";
//! * with a witness — "the issuer cannot show me a head that nobody else was shown".
//!
//! That is the difference between detection later and refusal now, at the counter.
//!
//! ## Who the witness is
//!
//! Not a second server run by whoever runs the issuer; that is a costume, not a witness.
//! The natural candidate is the party B14 already treats as the moat: the market
//! association, the co-op, the motor-park union. It is a real second party, and it is the
//! group a split view would be used against, so its incentive points the right way. This
//! module is `no_std` and signs through [`Signer`], exactly like the issuer and payer
//! sides, so a witness can be an association officer's phone rather than a server.
//!
//! A witness colluding with the issuer buys nothing back. Worth stating plainly rather
//! than overselling: what collusion costs the issuer is a co-conspirator inside the
//! community it is defrauding.
//!
//! ## Why the cosignature is domain-separated
//!
//! The issuer signs [`Checkpoint::body_digest`]. If a witness signed that same digest, an
//! issuer signature and a witness signature would be signatures over an *identical
//! message* — so any key that ever served both roles (a reused device key, a witness later
//! promoted to issuer) would make every cosignature a valid issuer signature on that
//! checkpoint. A witness could mint history. So a cosignature commits to its own body —
//! which witness, which checkpoint, when — hashed under a fixed tag
//! ([`COSIGN_DOMAIN`]). Key hygiene is then a good practice rather than the thing holding
//! the roof up.
//!
//! ## Cosignatures are additive, never identity
//!
//! A checkpoint's identity stays its own body digest. Two devices holding the same
//! checkpoint with *different* sets of cosignatures — one collected before a witness
//! replied, one after — hold the same checkpoint, and must never look like equivocation.
//! That invariant is asserted in `tests/witness.rs`.

use crate::checkpoint::{
    verify_checkpoint, Checkpoint, CheckpointError, CheckpointTracker, CheckpointVerdict,
    EquivocationProof,
};
use crate::codec::{Decoder, Encoder};
use crate::crypto::{CryptoError, PubKeyBytes, SigBytes, Signer, Verifier};
use crate::types::{DecodeError, Hash};
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Domain tag mixed into every cosignature's signing digest. See the module docs for why
/// this exists and what breaks without it.
pub const COSIGN_DOMAIN: &[u8] = b"igopay-cosign-v1";

/// Largest cosignature set a device will accept on one checkpoint.
///
/// A decoder cap, not a policy: witness sets are small by nature, and an unbounded array
/// is a cheap way to make a phone do elliptic-curve work all day.
pub const MAX_COSIGNATURES: usize = 16;

// ---------------------------------------------------------------------------
// Cosignature. keys:
// 0=witness_pubkey, 1=issuer_pubkey, 2=checkpoint_digest, 3=signed_at, 4=sig_witness
// The signed body is keys 0..=3, hashed under COSIGN_DOMAIN.
// ---------------------------------------------------------------------------

/// One witness's statement: "under this issuer, at this checkpoint's position, this is the
/// only head I have ever signed."
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cosignature {
    pub witness_pubkey: PubKeyBytes,
    /// Whose history is being attested to.
    ///
    /// Load-bearing, and not obvious. A [`Checkpoint`]'s body carries no issuer identity —
    /// it does not need to, because verifying it takes the issuer's key from outside — so two
    /// issuers that publish the same block list at the same position produce **byte-identical
    /// checkpoint bodies**. For an empty list at genesis that is trivially easy. Without this
    /// field, a cosignature naming only the digest would fit both, so any issuer could staple
    /// a rival's witness attestation onto its own history and appear witnessed; worse, a
    /// witness legitimately watching both would look like it had signed two heads at one
    /// position. Naming the issuer makes the statement say what it means.
    pub issuer_pubkey: PubKeyBytes,
    /// [`Checkpoint::body_digest`] of the checkpoint being cosigned.
    pub checkpoint_digest: Hash,
    /// The witness's own clock when it signed. Advisory, like the issuer's `issued_at`: no
    /// rule here depends on it, because it is not evidence of anything.
    pub signed_at: u64,
    pub sig_witness: SigBytes,
}

impl Cosignature {
    fn encode_common(&self, e: &mut Encoder, include_sig: bool) {
        e.map_head(if include_sig { 5 } else { 4 });
        e.map_key(0);
        e.bytes(&self.witness_pubkey);
        e.map_key(1);
        e.bytes(&self.issuer_pubkey);
        e.map_key(2);
        e.bytes(&self.checkpoint_digest);
        e.map_key(3);
        e.u64(self.signed_at);
        if include_sig {
            e.map_key(4);
            e.bytes(&self.sig_witness);
        }
    }

    /// Encode the signed body (keys 0..=3).
    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, false);
        e.into_bytes()
    }

    /// What the witness signs: `SHA-256(COSIGN_DOMAIN || body)`.
    ///
    /// The tag is not on the wire — it is a constant every implementation knows — but it is
    /// what keeps this signature from also being a valid signature over anything else in
    /// the protocol.
    pub fn signing_digest(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(COSIGN_DOMAIN);
        h.update(self.encode_body());
        h.finalize().into()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, true);
        e.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let c = Self::decode(&mut d)?;
        d.finish()?;
        Ok(c)
    }

    fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 5 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut witness = None;
        let mut issuer = None;
        let mut digest = None;
        let mut signed_at = None;
        let mut sig = None;
        for _ in 0..5 {
            match d.map_key(&mut last)? {
                0 => witness = Some(d.bytes_fixed::<33>()?),
                1 => issuer = Some(d.bytes_fixed::<33>()?),
                2 => digest = Some(d.bytes_fixed::<32>()?),
                3 => signed_at = Some(d.u64()?),
                4 => sig = Some(d.bytes_fixed::<64>()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(Cosignature {
            witness_pubkey: witness.ok_or(DecodeError::MissingField(0))?,
            issuer_pubkey: issuer.ok_or(DecodeError::MissingField(1))?,
            checkpoint_digest: digest.ok_or(DecodeError::MissingField(2))?,
            signed_at: signed_at.ok_or(DecodeError::MissingField(3))?,
            sig_witness: sig.ok_or(DecodeError::MissingField(4))?,
        })
    }

    /// Verify this cosignature against the witness key it names.
    pub fn verify<V: Verifier>(&self, verifier: &V) -> Result<(), CheckpointError> {
        verifier
            .verify_prehash(
                &self.witness_pubkey,
                &self.signing_digest(),
                &self.sig_witness,
            )
            .map_err(|e| match e {
                CryptoError::HighS => CheckpointError::MalleableSignature,
                _ => CheckpointError::BadWitnessSignature,
            })
    }
}

// ---------------------------------------------------------------------------
// WitnessedCheckpoint. keys: 0=checkpoint, 1=cosignatures
// ---------------------------------------------------------------------------

/// A checkpoint plus the cosignatures collected for it: what the issuer actually
/// distributes alongside a block list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedCheckpoint {
    pub checkpoint: Checkpoint,
    /// Strictly ascending by `witness_pubkey` — canonical, and it stops one witness being
    /// repeated to make coverage look wider than it is.
    pub cosignatures: Vec<Cosignature>,
}

impl WitnessedCheckpoint {
    /// A checkpoint with no cosignatures yet. Valid, and honest about what it is: the
    /// unwitnessed path still works, it just carries less assurance.
    pub fn new(checkpoint: Checkpoint) -> Self {
        WitnessedCheckpoint {
            checkpoint,
            cosignatures: Vec::new(),
        }
    }

    /// Attach a cosignature, keeping the set canonical. Replaces an existing entry from the
    /// same witness (a re-signature of the same checkpoint is the same statement) and
    /// returns `false` if it names a different checkpoint.
    pub fn attach(&mut self, cosig: Cosignature) -> bool {
        if cosig.checkpoint_digest != self.checkpoint.body_digest() {
            return false;
        }
        match self
            .cosignatures
            .binary_search_by(|c| c.witness_pubkey.cmp(&cosig.witness_pubkey))
        {
            Ok(i) => self.cosignatures[i] = cosig,
            Err(i) => self.cosignatures.insert(i, cosig),
        }
        true
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map_head(2);
        e.map_key(0);
        // The checkpoint's own encoding is already canonical; append verbatim.
        e.raw(&self.checkpoint.encode());
        e.map_key(1);
        e.array_head(self.cosignatures.len());
        for c in &self.cosignatures {
            e.raw(&c.encode());
        }
        e.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let n = d.map_head()?;
        if n != 2 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut checkpoint = None;
        let mut cosignatures = None;
        for _ in 0..2 {
            match d.map_key(&mut last)? {
                0 => checkpoint = Some(Checkpoint::decode(&mut d)?),
                1 => {
                    let count = d.array_head()?;
                    // Checked before the loop so a huge claimed count cannot drive a large
                    // allocation before it fails.
                    if count > MAX_COSIGNATURES {
                        return Err(DecodeError::WrongArrayLen);
                    }
                    let mut v = Vec::new();
                    for _ in 0..count {
                        v.push(Cosignature::decode(&mut d)?);
                    }
                    cosignatures = Some(v);
                }
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        d.finish()?;
        Ok(WitnessedCheckpoint {
            checkpoint: checkpoint.ok_or(DecodeError::MissingField(0))?,
            cosignatures: cosignatures.ok_or(DecodeError::MissingField(1))?,
        })
    }

    /// Structural checks that need no keys: canonical ordering, and every cosignature
    /// naming *this* checkpoint.
    fn check_shape(&self) -> Result<(), CheckpointError> {
        let digest = self.checkpoint.body_digest();
        for w in self.cosignatures.windows(2) {
            if w[0].witness_pubkey >= w[1].witness_pubkey {
                return Err(CheckpointError::CosignaturesNotSorted);
            }
        }
        for c in &self.cosignatures {
            if c.checkpoint_digest != digest {
                return Err(CheckpointError::CosignatureForAnotherCheckpoint);
            }
        }
        Ok(())
    }
}
/// How much independent attestation a checkpoint arrived with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessCoverage {
    /// Distinct **trusted** witnesses that cosigned it.
    pub witnesses: usize,
    /// Cosignatures from keys this device does not know, and therefore did not count.
    ///
    /// Not an error — witness sets differ per deployment and a device is not required to
    /// know every one — but worth surfacing, because a device seeing many unknown cosigners
    /// is probably configured with a stale witness list.
    pub unknown: usize,
}

impl WitnessCoverage {
    /// Did at least one trusted witness attest to this head?
    ///
    /// Deliberately a *report*, not a gate: what a thin margin of attestation should cost a
    /// payer is a limits question (B3/B14), and limits belong to tiering. A device that
    /// refused every unwitnessed checkpoint would also refuse every honest one during a
    /// witness outage, and would then be running on an older block list — failing open on
    /// revocation to protect against equivocation, which is the wrong trade.
    pub fn is_witnessed(&self) -> bool {
        self.witnesses > 0
    }
}

/// Verify a witnessed checkpoint: the issuer's signature, the structure, and every
/// cosignature from a witness this device trusts.
///
/// Cosignatures from unknown keys are counted separately and otherwise ignored. A bad
/// signature from a *trusted* witness is an error, not a silent zero — it means the artefact
/// was tampered with or that key is compromised, and both deserve to be loud.
pub fn verify_witnessed<V: Verifier>(
    witnessed: &WitnessedCheckpoint,
    issuer_pubkey: &PubKeyBytes,
    trusted_witnesses: &[PubKeyBytes],
    verifier: &V,
) -> Result<WitnessCoverage, CheckpointError> {
    witnessed.check_shape()?;
    verify_checkpoint(&witnessed.checkpoint, issuer_pubkey, verifier)?;

    let mut witnesses = 0;
    let mut unknown = 0;
    for c in &witnessed.cosignatures {
        if &c.issuer_pubkey != issuer_pubkey {
            return Err(CheckpointError::CosignatureForAnotherIssuer);
        }
        if trusted_witnesses.contains(&c.witness_pubkey) {
            c.verify(verifier)?;
            witnesses += 1;
        } else {
            unknown += 1;
        }
    }
    Ok(WitnessCoverage { witnesses, unknown })
}

/// Install a block list with its witnessed checkpoint: the recommended device-side path.
///
/// Does what [`crate::checkpoint::install_checkpointed_list`] does, and additionally reports
/// how much independent attestation the head carried. One call rather than three, for the
/// reason the block-list check lives inside `verify_promise`: a step an app has to remember
/// is a step that will be forgotten, and the failure looks like success.
///
/// Coverage is **returned, not enforced**. See [`WitnessCoverage::is_witnessed`].
pub fn install_witnessed_list<V: Verifier>(
    list: &crate::blocklist::SignedBlockList,
    witnessed: &WitnessedCheckpoint,
    issuer_pubkey: &PubKeyBytes,
    trusted_witnesses: &[PubKeyBytes],
    verifier: &V,
    current_epoch: Option<u64>,
) -> Result<(crate::blocklist::InstalledBlockList, WitnessCoverage), CheckpointError> {
    let coverage = verify_witnessed(witnessed, issuer_pubkey, trusted_witnesses, verifier)?;
    let installed = crate::checkpoint::install_checkpointed_list(
        list,
        &witnessed.checkpoint,
        issuer_pubkey,
        verifier,
        current_epoch,
    )?;
    Ok((installed, coverage))
}

// ---------------------------------------------------------------------------
// The witness itself.
// ---------------------------------------------------------------------------

/// Why a witness declined to cosign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WitnessRefusal {
    /// The checkpoint is not one this witness can act on — not signed by the issuer it
    /// watches, or structurally invalid.
    Unusable(CheckpointError),
    /// A **different** checkpoint is already cosigned at this position. The witness refuses
    /// and hands back the proof, which is the entire point of it existing.
    ///
    /// Publish this. A refusal nobody hears is just a missing signature, and a missing
    /// signature looks like an outage.
    Equivocation(Box<EquivocationProof>),
}

/// A witness's memory and its one rule.
///
/// Wraps a [`CheckpointTracker`] retaining everything, so the rule "one head per position"
/// is enforced by the same comparison logic devices use — and so a refusal comes with a
/// portable proof rather than an opinion. Reusing the tracker also means a witness will not
/// cosign across a broken chain link.
///
/// **This state must be persisted.** A witness that forgets a position can be talked into
/// cosigning a second head there, which is exactly the failure it exists to prevent. The
/// cost of never forgetting is about 320 bytes per publication (the checkpoint plus its
/// cosignature) — around 3 MB a year at hourly publication. Write down [`Self::seen`] and
/// [`Self::issued`]; read them back with [`Self::resume`], which re-verifies every byte
/// rather than trusting the file.
#[derive(Debug, Clone)]
pub struct WitnessLog {
    tracker: CheckpointTracker,
    witness_pubkey: PubKeyBytes,
    issued: BTreeMap<u64, Cosignature>,
}

impl WitnessLog {
    /// A witness holding `witness_pubkey`, watching the issuer at `issuer_pubkey`.
    pub fn new(witness_pubkey: PubKeyBytes, issuer_pubkey: PubKeyBytes) -> Self {
        WitnessLog {
            tracker: CheckpointTracker::retaining_all(issuer_pubkey),
            witness_pubkey,
            issued: BTreeMap::new(),
        }
    }

    /// Restore a witness from persisted state, re-verifying all of it.
    ///
    /// This type's whole value is memory across restarts, so a witness that could only ever
    /// be constructed empty would be a witness whose one rule expires every time its process
    /// does. Restoring is therefore part of the protocol, not a convenience: the counterpart
    /// to [`crate::checkpoint::CheckpointTracker`] being an in-memory model of what an app
    /// persists.
    ///
    /// Nothing is trusted for having been stored. Every checkpoint is re-verified against
    /// the issuer key and re-compared with the ones before it, and every cosignature is
    /// re-verified against the witness key — so state that was tampered with on disk is
    /// refused at load rather than believed and then signed on top of. It fails exactly the
    /// way [`cosign`](Self::cosign) fails, including handing back an
    /// [`EquivocationProof`] if the stored history contradicts itself.
    ///
    /// Two rules that are easy to miss:
    ///
    /// * A cosignature naming a checkpoint not present in `seen` is **refused**, not
    ///   ignored. A witness that kept a signature but forgot what it signed could not
    ///   produce a proof at that position ([`conflicting`](Self::conflicting)) — it would
    ///   hold a statement it can no longer defend, which is worse than holding nothing.
    /// * If `issued` contains more than one cosignature for a position, the **first** is
    ///   kept. Re-signing the same head is the same statement, and keeping the earliest
    ///   makes the restored witness agree with whatever was distributed first.
    pub fn resume<V: Verifier>(
        witness_pubkey: PubKeyBytes,
        issuer_pubkey: PubKeyBytes,
        seen: &[Checkpoint],
        issued: &[Cosignature],
        verifier: &V,
    ) -> Result<Self, WitnessRefusal> {
        let mut log = WitnessLog::new(witness_pubkey, issuer_pubkey);

        for cp in seen {
            match log.tracker.offer(cp, verifier) {
                Err(e) => return Err(WitnessRefusal::Unusable(e)),
                Ok(CheckpointVerdict::Equivocation(proof)) => {
                    return Err(WitnessRefusal::Equivocation(proof))
                }
                Ok(_) => {}
            }
        }

        for cosig in issued {
            if cosig.witness_pubkey != witness_pubkey {
                return Err(WitnessRefusal::Unusable(
                    CheckpointError::BadWitnessSignature,
                ));
            }
            if cosig.issuer_pubkey != issuer_pubkey {
                return Err(WitnessRefusal::Unusable(
                    CheckpointError::CosignatureForAnotherIssuer,
                ));
            }
            let seq = log.tracker.position_of(&cosig.checkpoint_digest).ok_or(
                WitnessRefusal::Unusable(CheckpointError::CosignatureForAnotherCheckpoint),
            )?;
            cosig.verify(verifier).map_err(WitnessRefusal::Unusable)?;
            log.issued.entry(seq).or_insert_with(|| cosig.clone());
        }

        Ok(log)
    }

    /// Cosign a checkpoint, or refuse.
    ///
    /// Idempotent: asked again about a checkpoint it already cosigned, the witness returns
    /// the cosignature it issued rather than a fresh one, so the artefact a device ends up
    /// holding does not depend on how many times the issuer asked.
    ///
    /// `signer` must hold `witness_pubkey`; anything else is refused, because a cosignature
    /// under an unexpected key is an outage that would only surface on somebody's phone.
    pub fn cosign<S: Signer, V: Verifier>(
        &mut self,
        checkpoint: &Checkpoint,
        now: u64,
        signer: &S,
        verifier: &V,
    ) -> Result<Cosignature, WitnessRefusal> {
        if signer.public_key() != self.witness_pubkey {
            return Err(WitnessRefusal::Unusable(
                CheckpointError::BadWitnessSignature,
            ));
        }

        match self.tracker.offer(checkpoint, verifier) {
            Err(e) => Err(WitnessRefusal::Unusable(e)),
            Ok(CheckpointVerdict::Equivocation(proof)) => Err(WitnessRefusal::Equivocation(proof)),
            Ok(CheckpointVerdict::Duplicate) => match self.issued.get(&checkpoint.seq) {
                // Already cosigned, and the tracker confirms it is the same checkpoint.
                Some(existing) => Ok(existing.clone()),
                // Held but never cosigned — possible if a caller offered it to the tracker
                // some other way. Sign it now.
                None => Ok(self.sign_and_record(checkpoint, now, signer)),
            },
            Ok(_) => Ok(self.sign_and_record(checkpoint, now, signer)),
        }
    }

    fn sign_and_record<S: Signer>(
        &mut self,
        checkpoint: &Checkpoint,
        now: u64,
        signer: &S,
    ) -> Cosignature {
        let mut cosig = Cosignature {
            witness_pubkey: self.witness_pubkey,
            issuer_pubkey: *self.tracker.issuer_pubkey(),
            checkpoint_digest: checkpoint.body_digest(),
            signed_at: now,
            sig_witness: [0u8; 64],
        };
        cosig.sig_witness = signer.sign_prehash(&cosig.signing_digest());
        self.issued.insert(checkpoint.seq, cosig.clone());
        cosig
    }

    /// The cosignature this witness issued at `seq`, if any. This is what a device asks for
    /// when it wants to check a checkpoint it was handed without one.
    pub fn cosignature_at(&self, seq: u64) -> Option<&Cosignature> {
        self.issued.get(&seq)
    }

    /// The checkpoint this witness cosigned at `seq`, retained so a later conflict can be
    /// *proven* rather than merely refused.
    pub fn checkpoint_at(&self, seq: u64) -> Option<&Checkpoint> {
        self.tracker.at(seq)
    }

    /// Does a checkpoint somebody was handed contradict what this witness has signed?
    ///
    /// The offline dispute path: a payee shows the witness a head, and the witness either
    /// recognises it or produces two of the issuer's own signatures.
    pub fn conflicting(&self, foreign: &Checkpoint) -> Option<EquivocationProof> {
        self.tracker
            .retained()
            .find_map(|mine| crate::checkpoint::detect_equivocation(mine, foreign))
    }

    pub fn witness_pubkey(&self) -> &PubKeyBytes {
        &self.witness_pubkey
    }

    /// The issuer this witness watches.
    pub fn issuer_pubkey(&self) -> &PubKeyBytes {
        self.tracker.issuer_pubkey()
    }

    /// The highest position this witness has seen.
    pub fn head(&self) -> Option<&Checkpoint> {
        self.tracker.head()
    }

    /// Every checkpoint retained, in position order — the first half of what
    /// [`resume`](Self::resume) needs written down.
    pub fn seen(&self) -> impl Iterator<Item = &Checkpoint> {
        self.tracker.retained()
    }

    /// Every cosignature issued, in position order — the second half.
    pub fn issued(&self) -> impl Iterator<Item = &Cosignature> {
        self.issued.values()
    }

    /// How many positions this witness has cosigned.
    pub fn len(&self) -> usize {
        self.issued.len()
    }

    pub fn is_empty(&self) -> bool {
        self.issued.is_empty()
    }
}
