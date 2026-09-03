//! Registration and tiering: the D4 admission gate, and the caps it deliberately does not set.
//!
//! Written as adversarial pairs, including the pairs that must **not** convict — a gate that
//! refuses everything passes every "must refuse" test and is still useless. The pair that
//! matters most is the key binding: a genuine attestation over the wrong key must be refused,
//! and the same attestation over its own key must be admitted.

mod common;

use common::TestSigner;
use igopay_core::crypto::{P256Verifier, PubKeyBytes, Signer, Verifier};
use igopay_issuer::registration::{
    decide_grant, inputs_from_registry, register, AttestationRefusal, AttestationVerdict,
    AttestationVerifier, ChallengeBook, ChallengeError, Guarantor, KycLevel, RefusingVerifier,
    RegistrationRefusal, RegistrationRequest, SecurityLevel, TieringInputs, TieringPolicy,
    VerifiedBoot, MIN_CHALLENGE_LEN,
};
use igopay_issuer::PromiseRegistry;

const NOW: u64 = 1_800_000_000;
const CHAIN: &[u8] = b"a chain the fake verifier does not read";

fn challenge() -> Vec<u8> {
    (1..=MIN_CHALLENGE_LEN as u8).collect()
}

/// A verifier whose verdict the test dictates.
///
/// The real one parses X.509 and checks Google's roots; that logic is tested in
/// `tools/test_verify_attestation.py` and deliberately does not live in this crate (see the
/// module docs on the seam). What *these* tests exercise is the policy above the seam, so
/// the seam is a knob here.
struct FakeVerifier(Result<AttestationVerdict, AttestationRefusal>);

impl AttestationVerifier for FakeVerifier {
    fn name(&self) -> &'static str {
        "fake"
    }

    fn verify(&self, _chain: &[u8], _now: u64) -> Result<AttestationVerdict, AttestationRefusal> {
        self.0.clone()
    }
}

fn verdict_for(key: PubKeyBytes) -> AttestationVerdict {
    AttestationVerdict {
        security_level: SecurityLevel::TrustedEnvironment,
        attested_pubkey: key,
        challenge: challenge(),
        verified_boot: VerifiedBoot::Verified,
        device_locked: true,
        // Two days out, matching what the Poco C71 actually produced (`09` §3).
        expires_at: NOW + 2 * 86_400,
    }
}

fn book_with_live_challenge() -> ChallengeBook {
    let mut book = ChallengeBook::new(300);
    book.issue(challenge(), NOW).expect("issue");
    book
}

fn request<'a>(payer: PubKeyBytes, chal: &'a [u8]) -> RegistrationRequest<'a> {
    RegistrationRequest {
        payer_pubkey: payer,
        handle: "adaeze".into(),
        attestation_chain: CHAIN,
        challenge: chal,
    }
}

// ---------------------------------------------------------------------------
// The admission gate
// ---------------------------------------------------------------------------

#[test]
fn a_tee_backed_chain_over_the_right_key_registers() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let verifier = FakeVerifier(Ok(verdict_for(payer)));
    let chal = challenge();

    let cert = register(
        &issuer,
        &verifier,
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect("a real hardware key over the right challenge registers");

    assert_eq!(cert.payer_pubkey, payer);
    assert_eq!(cert.handle, "adaeze");
}

#[test]
fn a_software_backed_chain_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let mut v = verdict_for(payer);
    v.security_level = SecurityLevel::Software;
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(v)),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("software attestation carries no hardware guarantee — Tier C");

    assert_eq!(
        err,
        RegistrationRefusal::NotHardwareBacked {
            level: SecurityLevel::Software
        }
    );
}

#[test]
fn strongbox_registers_too_because_the_gate_is_binary() {
    // The pair that must not convict. StrongBox is rarer and stronger, and it earns exactly
    // the same admission as TEE — the gate asks one question, not two.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let mut v = verdict_for(payer);
    v.security_level = SecurityLevel::StrongBox;
    let chal = challenge();

    assert!(register(
        &issuer,
        &FakeVerifier(Ok(v)),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// The check the whole gate rests on
// ---------------------------------------------------------------------------

#[test]
fn a_genuine_attestation_over_a_different_key_is_refused() {
    // The attack this stops: take any real attestation — your own, a friend's, one lifted
    // from a log — and submit it alongside a SOFTWARE key for certification. The chain
    // verifies perfectly, roots to Google, is in date, and attests to hardware. It just
    // attests to hardware holding a different key.
    let issuer = TestSigner::from_seed(1);
    let attested = TestSigner::from_seed(2).public_key();
    let submitted = TestSigner::from_seed(3).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(attested))),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(submitted, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("an attestation over someone else's key proves nothing about this one");

    assert_eq!(
        err,
        RegistrationRefusal::AttestedKeyIsNotTheKeyBeingCertified {
            attested,
            requested: submitted
        }
    );
}

#[test]
fn the_same_attestation_over_its_own_key_registers() {
    // The half that must not convict: the check above must be about the *binding*, not about
    // rejecting anything that looks unusual.
    let issuer = TestSigner::from_seed(1);
    let key = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    assert!(register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(key))),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(key, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// Challenges
// ---------------------------------------------------------------------------

#[test]
fn a_challenge_that_was_never_issued_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(payer))),
        &mut ChallengeBook::new(300),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("a challenge this issuer never handed out");

    assert_eq!(
        err,
        RegistrationRefusal::Challenge(ChallengeError::NotIssued)
    );
}

#[test]
fn a_challenge_cannot_be_redeemed_twice() {
    let mut book = book_with_live_challenge();
    assert!(book.redeem(&challenge(), NOW).is_ok());
    assert_eq!(
        book.redeem(&challenge(), NOW),
        Err(ChallengeError::NotIssued),
        "single use is the property; the second attempt sees nothing outstanding"
    );
}

#[test]
fn a_failed_registration_still_burns_the_challenge() {
    // Deliberate, and the reason is grinding: if a failure left the challenge live, an
    // attacker could keep trying attestations against one challenge until one was accepted.
    // An honest device pays one extra round trip instead.
    let issuer = TestSigner::from_seed(1);
    let attested = TestSigner::from_seed(2).public_key();
    let submitted = TestSigner::from_seed(3).public_key();
    let mut book = book_with_live_challenge();
    let chal = challenge();

    assert!(register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(attested))),
        &mut book,
        &TieringPolicy::default(),
        &request(submitted, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .is_err());

    assert_eq!(
        book.outstanding(),
        0,
        "the challenge was spent, not returned"
    );
}

#[test]
fn an_expired_challenge_is_refused() {
    let mut book = ChallengeBook::new(300);
    book.issue(challenge(), NOW).expect("issue");
    assert_eq!(
        book.redeem(&challenge(), NOW + 301),
        Err(ChallengeError::Expired)
    );
}

#[test]
fn a_challenge_inside_its_window_is_accepted() {
    let mut book = ChallengeBook::new(300);
    book.issue(challenge(), NOW).expect("issue");
    assert!(book.redeem(&challenge(), NOW + 300).is_ok());
}

#[test]
fn a_short_challenge_is_refused_at_issue() {
    let mut book = ChallengeBook::new(300);
    let short = vec![7u8; MIN_CHALLENGE_LEN - 1];
    assert_eq!(
        book.issue(short, NOW),
        Err(ChallengeError::TooShort {
            len: MIN_CHALLENGE_LEN - 1
        })
    );
}

#[test]
fn an_all_zero_challenge_is_refused_at_issue() {
    // Far more likely to be an uninitialised buffer than a draw from a CSPRNG, and a
    // predictable challenge lets an attestation be prepared before it is asked for.
    let mut book = ChallengeBook::new(300);
    assert_eq!(
        book.issue(vec![0u8; MIN_CHALLENGE_LEN], NOW),
        Err(ChallengeError::NotRandom)
    );
}

#[test]
fn reissuing_a_live_challenge_is_refused() {
    let mut book = book_with_live_challenge();
    assert_eq!(
        book.issue(challenge(), NOW),
        Err(ChallengeError::AlreadyIssued),
        "two registrations sharing one challenge is the thing a challenge prevents"
    );
}

#[test]
fn an_attestation_echoing_another_sessions_challenge_is_refused() {
    // The chain is genuine and the key is right; the attestation is simply a recording of a
    // different session.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let mut v = verdict_for(payer);
    v.challenge = vec![0xAA; MIN_CHALLENGE_LEN];
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(v)),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("the attestation is about another session");

    assert!(matches!(
        err,
        RegistrationRefusal::ChallengeNotEchoed { .. }
    ));
}

#[test]
fn dropping_expired_challenges_is_housekeeping_and_not_a_gate() {
    // `redeem` already refuses an expired challenge, so forgetting to sweep can waste memory
    // but can never admit anybody. Asserted so a future optimisation cannot quietly make the
    // sweep load-bearing.
    let mut book = ChallengeBook::new(300);
    book.issue(challenge(), NOW).expect("issue");
    assert_eq!(book.outstanding(), 1);
    book.drop_expired(NOW + 301);
    assert_eq!(book.outstanding(), 0);
    assert_eq!(
        book.redeem(&challenge(), NOW + 1),
        Err(ChallengeError::NotIssued)
    );
}

// ---------------------------------------------------------------------------
// D4, as an executable claim
// ---------------------------------------------------------------------------

#[test]
fn raising_attestation_from_tee_to_strongbox_does_not_change_the_cap() {
    // This is D4 written as a test rather than a paragraph. `TieringInputs` has no
    // attestation field, so the only way to attempt this is to register twice with different
    // hardware and compare — and the caps must match exactly.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let policy = TieringPolicy::default();
    let inputs = TieringInputs {
        kyc: KycLevel::Phone,
        fork_free_promises: 40,
        guarantor: Guarantor::None,
        fork_on_record: false,
        seq_at_issue: 40,
    };
    let chal = challenge();

    let mut caps = vec![];
    for level in [SecurityLevel::TrustedEnvironment, SecurityLevel::StrongBox] {
        let mut v = verdict_for(payer);
        v.security_level = level;
        let cert = register(
            &issuer,
            &FakeVerifier(Ok(v)),
            &mut book_with_live_challenge(),
            &policy,
            &request(payer, &chal),
            &inputs,
            NOW,
        )
        .expect("both levels clear the gate");
        caps.push(cert.per_payment_cap);
    }

    assert_eq!(
        caps[0], caps[1],
        "attestation is an admission gate, not a dial (09 §3, D4)"
    );
}

// ---------------------------------------------------------------------------
// Tiering
// ---------------------------------------------------------------------------

#[test]
fn kyc_raises_the_cap() {
    let policy = TieringPolicy::default();
    let cap = |kyc| {
        decide_grant(
            &policy,
            &TieringInputs {
                kyc,
                ..TieringInputs::cold_start()
            },
            NOW,
        )
        .per_payment_cap
    };

    assert!(cap(KycLevel::Anonymous) < cap(KycLevel::Phone));
    assert!(cap(KycLevel::Phone) < cap(KycLevel::Documented));
    assert!(cap(KycLevel::Documented) < cap(KycLevel::BankVerified));
}

#[test]
fn clean_history_raises_the_cap() {
    let policy = TieringPolicy::default();
    let cold = decide_grant(&policy, &TieringInputs::cold_start(), NOW);
    let seasoned = decide_grant(
        &policy,
        &TieringInputs {
            fork_free_promises: 50,
            ..TieringInputs::cold_start()
        },
        NOW,
    );
    assert!(
        seasoned.per_payment_cap > cold.per_payment_cap,
        "earned history is the input a fraudster cannot shortcut"
    );
}

#[test]
fn history_cannot_climb_past_the_kyc_ceiling() {
    let policy = TieringPolicy::default();
    let grant = decide_grant(
        &policy,
        &TieringInputs {
            kyc: KycLevel::Anonymous,
            fork_free_promises: 100_000,
            ..TieringInputs::cold_start()
        },
        NOW,
    );
    assert_eq!(
        grant.per_payment_cap, policy.ceiling.anonymous,
        "history earns trust; it does not earn its way out of a KYC band"
    );
}

#[test]
fn a_guarantor_adds_to_the_cap() {
    let policy = TieringPolicy::default();
    let alone = decide_grant(
        &policy,
        &TieringInputs {
            kyc: KycLevel::Phone,
            ..TieringInputs::cold_start()
        },
        NOW,
    );
    let vouched = decide_grant(
        &policy,
        &TieringInputs {
            kyc: KycLevel::Phone,
            guarantor: Guarantor::Vouched { guarantor_tier: 4 },
            ..TieringInputs::cold_start()
        },
        NOW,
    );
    assert!(vouched.per_payment_cap > alone.per_payment_cap);
}

#[test]
fn an_absurd_history_saturates_rather_than_overflowing() {
    let policy = TieringPolicy::default();
    let grant = decide_grant(
        &policy,
        &TieringInputs {
            kyc: KycLevel::BankVerified,
            fork_free_promises: u64::MAX,
            guarantor: Guarantor::Vouched { guarantor_tier: 5 },
            fork_on_record: false,
            seq_at_issue: u64::MAX,
        },
        u64::MAX,
    );
    assert_eq!(grant.per_payment_cap, policy.ceiling.bank_verified);
    assert_eq!(grant.not_after, u64::MAX, "saturating, not wrapping");
}

#[test]
fn a_fork_on_record_gives_a_zero_cap() {
    let policy = TieringPolicy::default();
    let grant = decide_grant(
        &policy,
        &TieringInputs {
            kyc: KycLevel::BankVerified,
            fork_free_promises: 5_000,
            guarantor: Guarantor::Vouched { guarantor_tier: 5 },
            fork_on_record: true,
            seq_at_issue: 5_000,
        },
        NOW,
    );
    assert_eq!(grant.per_payment_cap, 0);
    assert_eq!(grant.tier, 0);
}

#[test]
fn a_fork_on_record_refuses_registration_outright() {
    // Not merely a cap of zero: no certificate at all, so no offline capability. Blocking is
    // evidence-driven, and this is the same rule applied at issuance.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(payer))),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs {
            fork_on_record: true,
            ..TieringInputs::cold_start()
        },
        NOW,
    )
    .expect_err("evidence beats hardware");

    assert_eq!(err, RegistrationRefusal::ForkOnRecord);
}

#[test]
fn tier_is_a_label_that_history_lifts_by_at_most_one() {
    let policy = TieringPolicy::default();
    let tier = |promises| {
        decide_grant(
            &policy,
            &TieringInputs {
                kyc: KycLevel::Phone,
                fork_free_promises: promises,
                ..TieringInputs::cold_start()
            },
            NOW,
        )
        .tier
    };
    assert_eq!(tier(0), 2);
    assert_eq!(tier(99), 2, "99 promises is still a warm-up");
    assert_eq!(tier(100), 3);
    assert_eq!(
        tier(1_000_000),
        3,
        "the label saturates; the cap does the work"
    );
}

// ---------------------------------------------------------------------------
// Boot integrity
// ---------------------------------------------------------------------------

#[test]
fn an_unlocked_bootloader_is_refused_by_default() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let mut v = verdict_for(payer);
    v.verified_boot = VerifiedBoot::Unverified;
    v.device_locked = false;
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Ok(v)),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("the OS protecting the key's access controls is not the one Google signed");

    assert!(matches!(err, RegistrationRefusal::BootNotVerified { .. }));
}

#[test]
fn an_unlocked_bootloader_registers_when_policy_allows_it() {
    // The pair that must not convict, and the reason the flag exists: a developer device is
    // a legitimate case, and it has to be opted into rather than happened upon.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let mut v = verdict_for(payer);
    v.verified_boot = VerifiedBoot::Unverified;
    v.device_locked = false;
    let chal = challenge();

    assert!(register(
        &issuer,
        &FakeVerifier(Ok(v)),
        &mut book_with_live_challenge(),
        &TieringPolicy {
            require_verified_boot: false,
            ..TieringPolicy::default()
        },
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .is_ok());
}

// ---------------------------------------------------------------------------
// The seam's own refusals, and its default
// ---------------------------------------------------------------------------

#[test]
fn the_refusing_verifier_admits_nobody() {
    // An issuer that forgets to configure a verifier must register no devices rather than
    // every device. Same failure direction as `NoOpSettlement` being unable to say `Settled`.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &RefusingVerifier,
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("no verifier configured");

    assert!(matches!(err, RegistrationRefusal::Attestation(_)));
}

#[test]
fn an_expired_chain_is_refused_with_its_own_reason() {
    // Carried through rather than flattened: "expired" means collect it again now, while
    // "not rooted to Google" means refuse this device. Losing the distinction would make the
    // two indistinguishable to whatever handles the refusal.
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Err(AttestationRefusal::Expired {
            expired_at: NOW - 1,
        })),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("stale evidence");

    assert_eq!(
        err,
        RegistrationRefusal::Attestation(AttestationRefusal::Expired {
            expired_at: NOW - 1
        })
    );
}

#[test]
fn a_chain_that_roots_nowhere_is_refused() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let err = register(
        &issuer,
        &FakeVerifier(Err(AttestationRefusal::NotRootedToGoogle)),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect_err("this is what a cheap faked attestation actually looks like");

    assert_eq!(
        err,
        RegistrationRefusal::Attestation(AttestationRefusal::NotRootedToGoogle)
    );
}

// ---------------------------------------------------------------------------
// What the certificate actually says
// ---------------------------------------------------------------------------

#[test]
fn the_issued_certificate_verifies_under_the_issuer_key() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let chal = challenge();

    let cert = register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(payer))),
        &mut book_with_live_challenge(),
        &TieringPolicy::default(),
        &request(payer, &chal),
        &TieringInputs::cold_start(),
        NOW,
    )
    .expect("registers");

    P256Verifier
        .verify_prehash(&issuer.public_key(), &cert.body_digest(), &cert.sig_issuer)
        .expect("a certificate no payee would accept is worse than none");
}

#[test]
fn the_issued_certificate_carries_the_decided_terms() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let policy = TieringPolicy::default();
    let inputs = TieringInputs {
        kyc: KycLevel::Documented,
        fork_free_promises: 12,
        guarantor: Guarantor::None,
        fork_on_record: false,
        seq_at_issue: 15,
    };
    let chal = challenge();

    let cert = register(
        &issuer,
        &FakeVerifier(Ok(verdict_for(payer))),
        &mut book_with_live_challenge(),
        &policy,
        &request(payer, &chal),
        &inputs,
        NOW,
    )
    .expect("registers");

    let grant = decide_grant(&policy, &inputs, NOW);
    assert_eq!(cert.per_payment_cap, grant.per_payment_cap);
    assert_eq!(cert.tier, grant.tier);
    assert_eq!(cert.not_before, NOW);
    assert_eq!(cert.not_after, NOW + policy.validity_secs);
    assert_eq!(
        cert.seq_at_issue, 15,
        "the chain position, not the count of promises seen"
    );
}

#[test]
fn the_certificate_window_is_short_by_design() {
    // The certificate is also the revocation mechanism for a payee with no network, so a
    // long window is a long time for a compromised key to keep working.
    let policy = TieringPolicy::default();
    assert!(
        policy.validity_secs <= 7 * 86_400,
        "a week is already generous for an offline revocation window"
    );
}

// ---------------------------------------------------------------------------
// Reading the inputs off the registry
// ---------------------------------------------------------------------------

#[test]
fn inputs_from_an_empty_registry_are_a_cold_start() {
    let issuer = TestSigner::from_seed(1);
    let payer = TestSigner::from_seed(2).public_key();
    let registry = PromiseRegistry::new(issuer.public_key());

    let inputs = inputs_from_registry(&registry, &payer, KycLevel::Phone, Guarantor::None);

    assert_eq!(inputs.fork_free_promises, 0);
    assert_eq!(inputs.seq_at_issue, 0);
    assert!(!inputs.fork_on_record);
    assert_eq!(inputs.kyc, KycLevel::Phone);
}
