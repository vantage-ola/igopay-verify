//! Deterministic in-process test signer and promise/certificate builders.
//!
//! This module is compiled only into the test binaries. It exists so the checked-in
//! adversarial vectors are reproducible byte-for-byte. It is NOT a production signer:
//! production keys live in Android Keystore / iOS Secure Enclave behind the
//! `Signer` trait and never appear in Rust.
//!
//! Each integration-test binary links this module and uses a different subset of
//! it, so `dead_code` is expected here.
#![allow(dead_code)]

use igopay_core::crypto::{PubKeyBytes, SigBytes, Signer};
use igopay_core::{Certificate, Promise, SlotGrant};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::scalar::IsHigh;

/// A deterministic P-256 signer seeded from a fixed 32-byte scalar.
pub struct TestSigner {
    sk: SigningKey,
}

impl TestSigner {
    /// Build a signer from a fixed non-zero seed. Distinct seeds ⇒ distinct keys.
    pub fn from_seed(seed: u8) -> Self {
        let mut bytes = [0u8; 32];
        bytes[31] = seed.max(1); // ensure non-zero scalar
        let sk = SigningKey::from_bytes(&bytes.into()).expect("valid scalar");
        TestSigner { sk }
    }

    /// Sign a prehash and return raw r‖s WITHOUT low-S canonicalization. Used to
    /// build the high-S / malleable-signature adversarial vector.
    pub fn sign_prehash_raw(&self, digest: &[u8; 32]) -> SigBytes {
        let sig: Signature = self.sk.sign_prehash(digest).expect("sign");
        sig.to_bytes().into()
    }

    /// Produce the malleated (r, n - s) form of a signature. The malleated form
    /// verifies equally well cryptographically but is high-S, so the core must
    /// reject it. Used to prove the anti-malleability invariant.
    pub fn malleate(sig: &SigBytes) -> SigBytes {
        let s = Signature::from_slice(sig).expect("valid sig");
        // Normalize to the low-S form, then flip to its high-S counterpart so the
        // result is deterministically high-S regardless of the input's S half.
        let low = s.normalize_s().unwrap_or(s);
        force_high_s(&low)
    }
}

/// Given a low-S signature, return the equally-valid high-S counterpart (r, n - s).
fn force_high_s(sig: &Signature) -> SigBytes {
    let r = sig.r();
    let s = sig.s();
    let neg_s = -*s.as_ref(); // n - s
    let high = Signature::from_scalars(*r.as_ref(), neg_s).expect("valid scalars");
    debug_assert!(bool::from(high.s().is_high()));
    high.to_bytes().into()
}

impl Signer for TestSigner {
    /// Production-shaped signing: always returns the low-S canonical r‖s.
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes {
        let sig: Signature = self.sk.sign_prehash(digest).expect("sign");
        let canonical = sig.normalize_s().unwrap_or(sig);
        canonical.to_bytes().into()
    }

    fn public_key(&self) -> PubKeyBytes {
        let vk = self.sk.verifying_key();
        let pt = vk.to_encoded_point(true); // compressed 33-byte SEC1
        pt.as_bytes().try_into().expect("33-byte compressed key")
    }
}

/// Build and issuer-sign a certificate.
#[allow(clippy::too_many_arguments)]
pub fn make_certificate(
    issuer: &TestSigner,
    payer: &TestSigner,
    handle: &str,
    tier: u64,
    per_payment_cap: u64,
    slot_grant: SlotGrant,
    seq_at_issue: u64,
    not_before: u64,
    not_after: u64,
) -> Certificate {
    let mut cert = Certificate {
        payer_pubkey: payer.public_key(),
        handle: handle.to_string(),
        tier,
        per_payment_cap,
        slot_grant,
        seq_at_issue,
        not_before,
        not_after,
        sig_issuer: [0u8; 64],
    };
    cert.sig_issuer = issuer.sign_prehash(&cert.body_digest());
    cert
}

/// Build and payer-sign a promise against an already-issued certificate.
#[allow(clippy::too_many_arguments)]
pub fn make_promise(
    payer: &TestSigner,
    cert: &Certificate,
    payee_pubkey: PubKeyBytes,
    amount: u64,
    currency: &str,
    nonce: &[u8],
    seq: u64,
    prev_hash: [u8; 32],
    slot: u64,
) -> Promise {
    let mut p = Promise {
        payer_cert: cert.clone(),
        payee_pubkey,
        amount,
        currency: currency.to_string(),
        nonce: nonce.to_vec(),
        seq,
        prev_hash,
        slot,
        sig_payer: [0u8; 64],
    };
    p.sig_payer = payer.sign_prehash(&p.body_digest());
    p
}
