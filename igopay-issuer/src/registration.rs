//! Registration (attestation → certificate) and the tiering that sets the caps.
//!
//! Phase 2's last two items, unblocked by the D4 measurement: the Poco C71 — the budget
//! handset the pilot targets — produces a genuine TEE-backed attestation chain that
//! verifies to Google's root (`research/09-phase0-results.md` §3). So a hardware
//! admission gate is viable on the device class that matters, which is what D4 had to
//! establish before this policy could be written rather than guessed.
//!
//! ## Why attestation is a gate and not a dial
//!
//! B18 originally proposed *attestation-scaled trust*: stronger hardware, bigger offline
//! cap. Two measurements killed it.
//!
//! * **StrongBox is absent from the target device class** (`09` §3), so there is no
//!   distribution to price against — Tier A is a rounding error in this market.
//! * **The chain expires in 13 days.** The certificate above the leaf is a Google remote
//!   key provisioning batch certificate, measured at 2026-08-24 → 2026-09-06 on the Poco.
//!   Continuous attestation-scaled trust would mean re-attesting to keep a cap justified,
//!   and there is nothing durable to re-attest against.
//!
//! So attestation answers exactly one question — *is this a real hardware key on a real
//! device, or not* — and the answer is binary. Caps come from the things that cannot be
//! bought: fork-free history, KYC, and who vouched for you (B14).
//!
//! That decision is enforced by the **type signature**, not by a comment:
//! [`decide_grant`] takes [`TieringInputs`], which has no attestation field at all. It is
//! not possible to make a cap depend on attestation strength without changing the shape of
//! this module, which is the point — a rule that lives only in prose is a rule that erodes.
//!
//! ## The attestation seam
//!
//! This crate does **not** parse X.509. [`AttestationVerifier`] is an interface, the same
//! discipline as [`crate::settlement::SettlementAdapter`] and [`crate::anchor::AnchorSink`],
//! and for a sharper reason here: `tools/verify_attestation.py` is the reference
//! implementation of the gate — signatures, validity windows, anchor, revocation, then the
//! KeyDescription — and it has a test suite that proves it rejects fakes. A second
//! implementation of chain verification inside this crate could disagree with it, and the
//! one thing worse than no gate is two gates that admit different devices.
//!
//! [`RefusingVerifier`] is the default, and it admits nobody. An issuer that forgets to
//! wire a real verifier registers no one, rather than registering everyone — the same
//! failure direction as `NoOpSettlement` being unable to report `Settled`.
//!
//! ## The check that actually matters
//!
//! A valid attestation chain proves *some* hardware key exists on *some* real device. It
//! says nothing about whether that key is the one being certified. Skip
//! [`RegistrationRefusal::AttestedKeyIsNotTheKeyBeingCertified`] and an attacker replays
//! any genuine attestation — their own, a friend's, one scraped from a log — while
//! submitting a **software** key for certification, and the gate waves them through.
//!
//! Everything else here is hygiene by comparison. That one comparison is the gate.

use crate::registry::PromiseRegistry;
use igopay_core::build::build_certificate;
use igopay_core::crypto::{P256Verifier, PubKeyBytes, Signer, Verifier};
use igopay_core::{Certificate, SlotGrant};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// The attestation seam
// ---------------------------------------------------------------------------

/// How the attested key is held, as reported by the platform's own attestation.
///
/// Ordered deliberately: [`SecurityLevel::Software`] is the refusal case, and both
/// hardware levels are treated **identically** for tiering. `StrongBox` is retained
/// because it is what the attestation says and discarding measured facts is how records
/// rot — not because it earns anything (`09` §3, D4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No hardware guarantee. Tier C: refuse.
    Software,
    /// TEE-backed Keystore. **The norm**, and what the target device class provides.
    TrustedEnvironment,
    /// Discrete secure element. Flagships only; earns nothing extra here.
    StrongBox,
}

impl SecurityLevel {
    /// Whether this level clears the admission gate at all.
    pub fn is_hardware_backed(&self) -> bool {
        matches!(
            self,
            SecurityLevel::TrustedEnvironment | SecurityLevel::StrongBox
        )
    }
}

/// Verified-boot state from the attestation's RootOfTrust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedBoot {
    /// Stock, signed OS with a locked bootloader.
    Verified,
    /// Custom OS signed by a key the user installed.
    SelfSigned,
    /// Bootloader unlocked.
    Unverified,
    /// Boot integrity check failed outright.
    Failed,
}

/// What a *successfully verified* attestation chain establishes.
///
/// Every field is a fact the chain asserted and the verifier confirmed. Nothing here is a
/// decision — decisions are made by [`register`] against a [`TieringPolicy`], so the
/// verifier can be swapped without moving any policy with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationVerdict {
    pub security_level: SecurityLevel,
    /// **The key the hardware attested to.** This is what makes the chain about *this*
    /// registration rather than about some device somewhere. See the module docs.
    pub attested_pubkey: PubKeyBytes,
    /// The challenge echoed back inside the attestation extension.
    pub challenge: Vec<u8>,
    pub verified_boot: VerifiedBoot,
    pub device_locked: bool,
    /// Tightest `notAfter` in the chain, as UTC seconds. Reported so a caller can see the
    /// freshness budget it is spending; on the target device class this is days, not years.
    pub expires_at: u64,
}

/// Why a chain was not accepted as evidence. These are the verifier's refusals, distinct
/// from [`RegistrationRefusal`] which are the *policy's*.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestationRefusal {
    /// A certificate in the chain is not signed by the next one up.
    BrokenChain { at: usize },
    /// The chain does not terminate at a published Google attestation root. This is the
    /// software-faked case, and it is the one cheap devices actually produce.
    NotRootedToGoogle,
    /// A certificate in the chain was outside its validity window at the time of the
    /// check. On Android this is ordinary rather than sinister: the batch certificate
    /// lives about a fortnight, so an attestation collected too long ago is stale
    /// evidence, not proof of tampering. Collect it again.
    Expired { expired_at: u64 },
    /// A serial in the chain is revoked or suspended on Google's status list.
    Revoked { serial: String },
    /// The leaf carries no KeyDescription extension, so it is not an attestation
    /// certificate at all.
    NoAttestationExtension,
    /// The chain parsed but something in it did not make sense.
    Malformed { detail: String },
}

/// Verifying an attestation chain. Implemented outside this crate on purpose.
///
/// The contract: return a verdict **only** if the chain verifies end to end, roots to a
/// published Google attestation root, is within its validity window at `now`, and carries
/// a parseable KeyDescription. Anything less is a refusal. An implementation that returns
/// a verdict for a chain it could not fully verify defeats the gate, and no amount of
/// policy above it can compensate.
pub trait AttestationVerifier {
    /// A stable name for logs and audit records, so a certificate can always be traced to
    /// the gate that admitted it.
    fn name(&self) -> &'static str;

    /// `chain` is the device's certificate chain, leaf first, in whatever encoding the
    /// implementation documents (DER or PEM). `now` is UTC seconds, injected rather than
    /// read, so validity is checked against the issuer's anchored clock and a test can
    /// place itself inside or outside a window.
    fn verify(&self, chain: &[u8], now: u64) -> Result<AttestationVerdict, AttestationRefusal>;
}

/// Admits nobody, ever.
///
/// The correct default: an issuer with no attestation verifier wired up must register no
/// one. The opposite default — accept everything until someone remembers to add the gate
/// — is the kind of thing that ships. Same reasoning as `NoOpSettlement` being structurally
/// unable to report `Settled`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RefusingVerifier;

impl AttestationVerifier for RefusingVerifier {
    fn name(&self) -> &'static str {
        "refusing (no verifier configured)"
    }

    fn verify(&self, _chain: &[u8], _now: u64) -> Result<AttestationVerdict, AttestationRefusal> {
        Err(AttestationRefusal::Malformed {
            detail: "no attestation verifier is configured, so nothing can be admitted".into(),
        })
    }
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

/// The minimum challenge length this crate will issue.
///
/// 16 bytes of CSPRNG output. The challenge is the only thing making an attestation about
/// *this* registration attempt rather than a recording of an earlier one, so it has to be
/// unguessable; a counter or a timestamp would let an attacker pre-generate an attestation
/// for a challenge the issuer has not asked for yet.
pub const MIN_CHALLENGE_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeError {
    /// Shorter than [`MIN_CHALLENGE_LEN`].
    TooShort { len: usize },
    /// All zero bytes. Almost certainly an uninitialised buffer rather than a draw from a
    /// CSPRNG, and worth refusing loudly instead of admitting a predictable challenge.
    NotRandom,
    /// Already issued and still outstanding. Reissuing a live challenge would let two
    /// registrations share one, which is the property the challenge exists to prevent.
    AlreadyIssued,
    /// Presented but never issued by this issuer.
    NotIssued,
    /// Issued, but outside its window by the time it came back.
    Expired,
}

/// Outstanding registration challenges.
///
/// In memory and non-persistent, like [`PromiseRegistry`] — a real service swaps in
/// storage behind the same three operations. What a schema must preserve is the part that
/// carries the security property: a challenge is redeemable **exactly once**, and that
/// has to hold across processes, so the store needs a unique constraint rather than a
/// read-then-write.
///
/// The issuer generates challenges; this type does not, because a pure library with no
/// randomness of its own cannot lie about where the entropy came from. The caller passes
/// CSPRNG bytes in and [`ChallengeBook::issue`] refuses the obvious mistakes.
#[derive(Debug, Clone)]
pub struct ChallengeBook {
    /// challenge → the UTC second it stops being redeemable.
    outstanding: BTreeMap<Vec<u8>, u64>,
    lifetime_secs: u64,
}

impl ChallengeBook {
    /// `lifetime_secs` should be short — this is the time between the issuer handing out a
    /// challenge and the device coming back with an attestation over it, which is one
    /// round trip, not a session.
    pub fn new(lifetime_secs: u64) -> Self {
        Self {
            outstanding: BTreeMap::new(),
            lifetime_secs,
        }
    }

    /// Record a freshly generated challenge as outstanding.
    pub fn issue(&mut self, challenge: Vec<u8>, now: u64) -> Result<(), ChallengeError> {
        if challenge.len() < MIN_CHALLENGE_LEN {
            return Err(ChallengeError::TooShort {
                len: challenge.len(),
            });
        }
        if challenge.iter().all(|b| *b == 0) {
            return Err(ChallengeError::NotRandom);
        }
        if self.outstanding.contains_key(&challenge) {
            return Err(ChallengeError::AlreadyIssued);
        }
        self.outstanding
            .insert(challenge, now.saturating_add(self.lifetime_secs));
        Ok(())
    }

    /// Spend a challenge. Succeeds at most once per issued challenge.
    ///
    /// Note what this deliberately does: it removes the challenge **before** the caller
    /// knows whether the rest of registration will succeed. A failed attempt therefore
    /// burns it. That is the point — if a challenge survived failure, an attacker could
    /// grind attestations against one live challenge until something got through, and the
    /// cost of the alternative is that an honest device asks for a new challenge and
    /// retries, which costs one round trip.
    pub fn redeem(&mut self, challenge: &[u8], now: u64) -> Result<(), ChallengeError> {
        match self.outstanding.remove(challenge) {
            None => Err(ChallengeError::NotIssued),
            Some(expires_at) if now > expires_at => Err(ChallengeError::Expired),
            Some(_) => Ok(()),
        }
    }

    /// Drop challenges nobody came back for. Housekeeping only — [`ChallengeBook::redeem`]
    /// already refuses an expired one, so forgetting to call this cannot admit anybody.
    pub fn drop_expired(&mut self, now: u64) {
        self.outstanding.retain(|_, expires_at| *expires_at >= now);
    }

    pub fn outstanding(&self) -> usize {
        self.outstanding.len()
    }
}

// ---------------------------------------------------------------------------
// Tiering inputs and policy
// ---------------------------------------------------------------------------

/// How well the issuer knows who this is.
///
/// `06` §3 has the progression: a phone number at install, BVN/NIN later for higher
/// tiers. These are the rungs, and they are about *identity*, not hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum KycLevel {
    /// A key and a handle. Nothing tying either to a person.
    Anonymous,
    /// A verified phone number.
    Phone,
    /// Phone plus an identity document on file.
    Documented,
    /// Phone plus BVN/NIN verified against the bank record.
    BankVerified,
}

/// Social collateral (B14): who is standing behind this payer.
///
/// This is the part that cannot be bought or faked at scale, which is exactly why it
/// carries weight that attestation no longer does. A guarantor countersigns and their own
/// standing absorbs the loss if the payer forks (`06` §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Guarantor {
    None,
    /// Vouched for by a payer at `guarantor_tier`, whose standing is at risk.
    Vouched {
        guarantor_tier: u64,
    },
}

/// Everything the cap is allowed to depend on.
///
/// **There is deliberately no attestation field.** D4 made the hardware check a binary
/// admission gate, and the way to keep a decision like that from eroding is to make the
/// wrong thing unrepresentable rather than merely discouraged. If someone later wants
/// attestation-scaled caps, they have to change this struct, and the module docs explaining
/// why it does not exist are right there in the diff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieringInputs {
    pub kyc: KycLevel,
    /// Promises on record with no fork. Earned history — the one input a fraudster cannot
    /// shortcut, because it takes real counterparties and real time.
    pub fork_free_promises: u64,
    pub guarantor: Guarantor,
    /// A fork proof exists for this payer. Refuse outright, whatever else is true.
    pub fork_on_record: bool,
    /// The payer's chain position at issuance, written into the certificate so a payee can
    /// price exposure *since* the certificate was issued (`seq - seq_at_issue`) rather than
    /// having to trust a running total. Kept separate from `fork_free_promises` because the
    /// two genuinely differ: promises reach the issuer only when a payee syncs, so the
    /// count seen can lag the chain position, and conflating them would understate the
    /// payer's position and overstate their exposure.
    pub seq_at_issue: u64,
}

impl TieringInputs {
    /// A brand-new payer: no history, no KYC, nobody vouching.
    pub fn cold_start() -> Self {
        Self {
            kyc: KycLevel::Anonymous,
            fork_free_promises: 0,
            guarantor: Guarantor::None,
            fork_on_record: false,
            seq_at_issue: 0,
        }
    }
}

/// Caps per KYC rung, in the **minor units of the certificate's currency**.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KycCaps {
    pub anonymous: u64,
    pub phone: u64,
    pub documented: u64,
    pub bank_verified: u64,
}

impl KycCaps {
    fn at(&self, kyc: KycLevel) -> u64 {
        match kyc {
            KycLevel::Anonymous => self.anonymous,
            KycLevel::Phone => self.phone,
            KycLevel::Documented => self.documented,
            KycLevel::BankVerified => self.bank_verified,
        }
    }
}

/// The dials, in one place, so a pilot can be retuned without touching the logic.
///
/// **The numbers in [`TieringPolicy::default`] are placeholders and should be treated as
/// such.** `06` §4.4 argues the cap should be continuous rather than a flat limit, and
/// gives the dials — but no field data exists yet to set them, and Phase 4 exists to
/// produce it. Shipping invented naira figures as though they were decided would be the
/// kind of false precision this repository tries not to accumulate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TieringPolicy {
    /// Starting cap for a payer with no history at all.
    pub base_cap: KycCaps,
    /// Cap added per fork-free promise on record.
    pub earned_per_clean_promise: u64,
    /// Hard ceiling per KYC rung, whatever the history or vouching says. History earns
    /// trust; it does not earn its way out of a KYC band.
    pub ceiling: KycCaps,
    /// What a vouch adds, before the ceiling is applied.
    pub guarantor_bonus: u64,
    /// Certificate lifetime. Short by design: the certificate is also the revocation
    /// mechanism for a payee with no network (`types::Certificate`), so a long window is
    /// a long time for a compromised key to keep working.
    pub validity_secs: u64,
    /// Slot granularity and how far ahead slots are granted.
    pub slot_granularity_secs: u64,
    pub slot_span_secs: u64,
    /// Whether an unlocked bootloader is refused.
    ///
    /// `tools/verify_attestation.py` reports verified-boot state as a *note* and still
    /// passes the hardware gate, which is right for a probe whose job is to describe a
    /// device. A registration gate has to decide, and the default here is stricter than
    /// the probe: an unlocked bootloader means the OS protecting the key's access controls
    /// is not the one Google signed. Set `false` deliberately, for a developer device.
    pub require_verified_boot: bool,
}

impl Default for TieringPolicy {
    fn default() -> Self {
        Self {
            // Placeholders. See the struct docs: Phase 4 sets these from field data.
            base_cap: KycCaps {
                anonymous: 2_000,
                phone: 10_000,
                documented: 50_000,
                bank_verified: 100_000,
            },
            earned_per_clean_promise: 100,
            ceiling: KycCaps {
                anonymous: 10_000,
                phone: 100_000,
                documented: 500_000,
                bank_verified: 2_000_000,
            },
            guarantor_bonus: 25_000,
            // One day. Long enough to be offline through a market day, short enough that
            // a revoked key stops working without every payee needing a lookup.
            validity_secs: 86_400,
            slot_granularity_secs: 3_600,
            slot_span_secs: 86_400,
            require_verified_boot: true,
        }
    }
}

/// What tiering decided. Everything a certificate needs except identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Informational band, carried in the certificate so a payee can *show* something
    /// meaningful ("3,400 promises, zero forks, tier 3" — `06` §3). The verifier enforces
    /// `per_payment_cap`, never this, so a tier cannot quietly become a second cap.
    pub tier: u64,
    pub per_payment_cap: u64,
    pub slot_grant: SlotGrant,
    pub not_before: u64,
    pub not_after: u64,
}

/// The tiering decision, as a pure function of things that are not hardware.
///
/// Separate from [`register`] because it is also the *refresh* path: a payer who has built
/// history comes back for a new certificate with better terms, and the same rules must
/// apply. Registration is just this function's cold-start case
/// ([`TieringInputs::cold_start`]).
pub fn decide_grant(policy: &TieringPolicy, inputs: &TieringInputs, now: u64) -> Grant {
    // A fork on record is not a smaller cap, it is the end of offline acceptance for this
    // payer. Blocking is evidence-driven (`registry`), and this is the same rule expressed
    // at issuance: no certificate, so no offline capability, until the evidence is
    // resolved by whatever process resolves it.
    let per_payment_cap = if inputs.fork_on_record {
        0
    } else {
        let earned = inputs
            .fork_free_promises
            .saturating_mul(policy.earned_per_clean_promise);
        let vouched = match inputs.guarantor {
            Guarantor::None => 0,
            Guarantor::Vouched { .. } => policy.guarantor_bonus,
        };
        policy
            .base_cap
            .at(inputs.kyc)
            .saturating_add(earned)
            .saturating_add(vouched)
            .min(policy.ceiling.at(inputs.kyc))
    };

    Grant {
        tier: derive_tier(inputs),
        per_payment_cap,
        slot_grant: SlotGrant {
            from: now,
            to: now.saturating_add(policy.slot_span_secs),
            granularity_secs: policy.slot_granularity_secs,
        },
        not_before: now,
        not_after: now.saturating_add(policy.validity_secs),
    }
}

/// The displayed band. KYC sets the floor, history can lift it by one, a fork drops it to
/// zero. Deliberately coarse: it is a label for a human at a market stall, not an input to
/// any check.
fn derive_tier(inputs: &TieringInputs) -> u64 {
    if inputs.fork_on_record {
        return 0;
    }
    let from_kyc = match inputs.kyc {
        KycLevel::Anonymous => 1,
        KycLevel::Phone => 2,
        KycLevel::Documented => 3,
        KycLevel::BankVerified => 4,
    };
    // 100 clean promises is a real trading history, not a warm-up.
    let earned = u64::from(inputs.fork_free_promises >= 100);
    (from_kyc + earned).min(5)
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

/// What a device asks for.
#[derive(Debug, Clone)]
pub struct RegistrationRequest<'a> {
    /// The public key to be certified. Must be the key the attestation attests to.
    pub payer_pubkey: PubKeyBytes,
    pub handle: String,
    /// The device's attestation chain, leaf first, in whatever encoding the configured
    /// [`AttestationVerifier`] documents.
    pub attestation_chain: &'a [u8],
    /// The challenge this issuer handed out, echoed by the device inside the attestation.
    pub challenge: &'a [u8],
}

/// Why registration was refused. Refusal means no certificate was issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationRefusal {
    /// The challenge was never issued, already spent, or timed out.
    Challenge(ChallengeError),
    /// The chain itself did not verify. The verifier's own reason is carried through
    /// rather than flattened, because "expired" and "not rooted to Google" call for
    /// completely different responses: retry now, versus refuse this device class.
    Attestation(AttestationRefusal),
    /// The chain verified but the challenge inside it is not the one we issued. The
    /// attestation is genuine and belongs to another session — a recording.
    ChallengeNotEchoed { expected: Vec<u8>, found: Vec<u8> },
    /// **The attested key is not the key being certified.** See the module docs: without
    /// this comparison a genuine attestation from any device admits a software key.
    AttestedKeyIsNotTheKeyBeingCertified {
        attested: PubKeyBytes,
        requested: PubKeyBytes,
    },
    /// Software-only attestation. Tier C, refuse (D4).
    NotHardwareBacked { level: SecurityLevel },
    /// Bootloader unlocked or a custom OS, and policy requires verified boot.
    BootNotVerified {
        state: VerifiedBoot,
        device_locked: bool,
    },
    /// A fork proof exists for this payer.
    ForkOnRecord,
    /// The certificate this issuer just built does not verify under its own key. Should be
    /// impossible; checked anyway, because the alternative is shipping a certificate every
    /// payee in the market refuses and finding out from a trader.
    SelfCheckFailed,
}

impl From<ChallengeError> for RegistrationRefusal {
    fn from(e: ChallengeError) -> Self {
        RegistrationRefusal::Challenge(e)
    }
}

/// Register a device: verify its attestation, decide its terms, issue its certificate.
///
/// The order of checks is deliberate. The challenge is spent first, so a replay cannot
/// buy an attacker repeated attempts against one live challenge; then the chain is
/// verified; then the two bindings that make the chain *mean* something — the echoed
/// challenge and, above all, the attested key. Only then does policy get a say.
///
/// `now` is UTC seconds from the issuer's anchored clock, injected rather than read
/// (`igopay_core::clock`).
pub fn register(
    issuer: &dyn Signer,
    verifier: &dyn AttestationVerifier,
    challenges: &mut ChallengeBook,
    policy: &TieringPolicy,
    request: &RegistrationRequest<'_>,
    inputs: &TieringInputs,
    now: u64,
) -> Result<Certificate, RegistrationRefusal> {
    // 1. Spend the challenge. Before any expensive work, and before any decision, so a
    //    failure downstream still costs the caller a round trip.
    challenges.redeem(request.challenge, now)?;

    // 2. The chain must verify on its own terms. Not our job; the seam's.
    let verdict = verifier
        .verify(request.attestation_chain, now)
        .map_err(RegistrationRefusal::Attestation)?;

    // 3. The attestation must be about this session.
    if verdict.challenge != request.challenge {
        return Err(RegistrationRefusal::ChallengeNotEchoed {
            expected: request.challenge.to_vec(),
            found: verdict.challenge,
        });
    }

    // 4. ...and about this key. The gate.
    if verdict.attested_pubkey != request.payer_pubkey {
        return Err(RegistrationRefusal::AttestedKeyIsNotTheKeyBeingCertified {
            attested: verdict.attested_pubkey,
            requested: request.payer_pubkey,
        });
    }

    // 5. The binary admission gate itself (D4).
    if !verdict.security_level.is_hardware_backed() {
        return Err(RegistrationRefusal::NotHardwareBacked {
            level: verdict.security_level,
        });
    }

    // 6. Boot integrity, if policy asks for it.
    if policy.require_verified_boot
        && (verdict.verified_boot != VerifiedBoot::Verified || !verdict.device_locked)
    {
        return Err(RegistrationRefusal::BootNotVerified {
            state: verdict.verified_boot,
            device_locked: verdict.device_locked,
        });
    }

    // 7. Evidence beats hardware. A payer with a fork on record gets nothing, however
    //    good their handset is.
    if inputs.fork_on_record {
        return Err(RegistrationRefusal::ForkOnRecord);
    }

    let grant = decide_grant(policy, inputs, now);
    let cert = build_certificate(
        issuer,
        request.payer_pubkey,
        request.handle.clone(),
        grant.tier,
        grant.per_payment_cap,
        grant.slot_grant,
        inputs.seq_at_issue,
        grant.not_before,
        grant.not_after,
    );

    // 8. Verify what we just built, against the same rule a phone applies. The publisher
    //    does the same thing with `install_checkpointed_list` before releasing a block
    //    list, for the same reason: an artefact every device refuses is worse than none.
    if P256Verifier
        .verify_prehash(&issuer.public_key(), &cert.body_digest(), &cert.sig_issuer)
        .is_err()
    {
        return Err(RegistrationRefusal::SelfCheckFailed);
    }

    Ok(cert)
}

/// Build [`TieringInputs`] from what the issuer already knows about a payer.
///
/// Convenience over the registry so a caller cannot forget the two questions that matter:
/// is this payer blocked, and how much clean history do they have.
pub fn inputs_from_registry(
    registry: &PromiseRegistry,
    payer_pubkey: &PubKeyBytes,
    kyc: KycLevel,
    guarantor: Guarantor,
) -> TieringInputs {
    TieringInputs {
        kyc,
        // Promises the issuer has actually seen. Not `highest_seq`, which a payer controls
        // and could inflate by claiming a high `seq`; this counts what was submitted and
        // verified, so history has to be earned with real counterparties.
        fork_free_promises: registry.digests_for_payer(payer_pubkey).len() as u64,
        guarantor,
        fork_on_record: registry.is_blocked(payer_pubkey),
        // One past the highest seq seen, which is where an honest payer's next promise
        // lands. A gap here is harmless: it makes exposure since issue look *larger*, and
        // erring toward more caution is the right direction for a figure a payee prices on.
        seq_at_issue: registry
            .highest_seq(payer_pubkey)
            .map_or(0, |s| s.saturating_add(1)),
    }
}
