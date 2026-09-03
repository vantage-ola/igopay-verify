//! Deterministic in-process signer and artefact builders for issuer tests.
//!
//! NOT a production signer: real keys live in Android Keystore / iOS Secure Enclave
//! behind `igopay_core::crypto::Signer` and never appear in Rust. This exists so the
//! issuer's vectors are reproducible byte-for-byte.
//!
//! (Known duplication: `igopay-core/tests/common/` and `igopay-ffi/tests/` carry
//! near-identical signers. Consolidating all three behind an optional `test-util`
//! feature on `igopay-core` is worthwhile cleanup, deliberately not bundled into this
//! change.)
#![allow(dead_code)]

use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::{Certificate, Promise, SlotGrant};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};

/// A deterministic P-256 signer seeded from a fixed 32-byte scalar.
pub struct TestSigner {
    sk: SigningKey,
}

impl TestSigner {
    pub fn from_seed(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1); // non-zero scalar
        TestSigner {
            sk: SigningKey::from_bytes(&bytes.into()).expect("valid scalar"),
        }
    }

    /// Given any valid signature, return its equally-valid **high-S** counterpart
    /// `(r, n - s)`. The core rejects high-S on verify, so this builds the malleability
    /// vector — used to prove the issuer refuses it too, since a malleated copy of an
    /// honest promise could otherwise masquerade as fork evidence.
    pub fn malleate(sig: &SigBytes) -> SigBytes {
        use p256::elliptic_curve::scalar::IsHigh;
        let s = Signature::from_slice(sig).expect("valid sig");
        let low = s.normalize_s().unwrap_or(s);
        let neg_s = -*low.s().as_ref(); // n - s
        let high = Signature::from_scalars(*low.r().as_ref(), neg_s).expect("valid scalars");
        debug_assert!(bool::from(high.s().is_high()));
        high.to_bytes().into()
    }
}

impl Signer for TestSigner {
    /// Production-shaped: always low-S canonical `r‖s`, as a Keystore/Enclave signer must
    /// be (the core rejects high-S on verify).
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        let sig: Signature = self.sk.sign_prehash(digest).expect("sign");
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

pub const GRANT_FROM: u64 = 1000;
pub const GRANT_TO: u64 = 1000 + 2880;

pub fn grant() -> SlotGrant {
    SlotGrant {
        from: GRANT_FROM,
        to: GRANT_TO,
        granularity_secs: 60,
    }
}

/// Issue a certificate through the core's blessed builder.
pub fn issue_cert(issuer: &TestSigner, payer: &TestSigner, seq_at_issue: u64) -> Certificate {
    igopay_core::build_certificate(
        issuer,
        payer.public_key(),
        "adunni".into(),
        2,
        50_000,
        grant(),
        seq_at_issue,
        0,
        100_000,
    )
}

/// Build a payer-signed promise with explicit chain fields.
#[allow(clippy::too_many_arguments)]
pub fn promise(
    payer: &TestSigner,
    cert: &Certificate,
    payee: PubKeyBytes,
    amount: u64,
    nonce: &[u8],
    seq: u64,
    prev_hash: [u8; 32],
    slot: u64,
) -> Promise {
    let mut p = Promise {
        payer_cert: cert.clone(),
        payee_pubkey: payee,
        amount,
        currency: "NGN".into(),
        nonce: nonce.to_vec(),
        seq,
        prev_hash,
        slot,
        sig_payer: [0u8; 64],
    };
    p.sig_payer = payer.sign_prehash(&p.body_digest());
    p
}
