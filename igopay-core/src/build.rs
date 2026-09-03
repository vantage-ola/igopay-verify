//! Constructing and signing artefacts (the payer/issuer side of the protocol).
//!
//! `verify` is the payee's half; this module is the other half — turning fields plus
//! a hardware-backed [`Signer`] into a signed [`Certificate`] or [`Promise`]. It is
//! the ONLY blessed way an app should build a signed artefact, so the "sign the
//! canonical body digest" step lives in one audited place instead of being
//! re-derived (and mis-derived) per platform.
//!
//! The core still never holds a private key: these helpers take a `&dyn Signer` (the
//! platform's Keystore / Secure Enclave wrapper) and call it to produce the
//! signature. They compute the exact same body digest the verifier recomputes, so a
//! freshly built artefact verifies by construction.
//!
//! Chain linkage (B2): a payer builds a *sequence* of promises, each `prev_hash`
//! pointing at the previous promise's body digest. [`PromiseBuilder`] carries a
//! running head so the caller cannot accidentally break the link or reuse a `seq`.

use crate::crypto::{PubKeyBytes, SigBytes, Signer};
use crate::types::{Certificate, Hash, Promise, SlotGrant};
use alloc::string::String;
use alloc::vec::Vec;

/// Build and issuer-sign a [`Certificate`].
///
/// The issuer is whoever controls `issuer` (a [`Signer`] over the pinned issuer
/// key). The returned certificate's `sig_issuer` is over its canonical body, so it
/// verifies against `issuer.public_key()`.
#[allow(clippy::too_many_arguments)]
pub fn build_certificate(
    issuer: &dyn Signer,
    payer_pubkey: PubKeyBytes,
    handle: String,
    tier: u64,
    per_payment_cap: u64,
    slot_grant: SlotGrant,
    seq_at_issue: u64,
    not_before: u64,
    not_after: u64,
) -> Certificate {
    let mut cert = Certificate {
        payer_pubkey,
        handle,
        tier,
        per_payment_cap,
        slot_grant,
        seq_at_issue,
        not_before,
        not_after,
        // Placeholder; overwritten below. It is NOT part of the signed body, so its
        // value here does not affect the digest.
        sig_issuer: [0u8; 64],
    };
    cert.sig_issuer = issuer.sign_prehash(&cert.body_digest());
    cert
}

/// The details of a single payment, minus the chain bookkeeping the builder tracks.
///
/// Grouped into a struct so [`PromiseBuilder::sign_next`] has a small, ordered
/// signature and the caller cannot transpose, say, `amount` and `slot`.
pub struct PaymentDetails {
    /// The payee this promise is bound to (kills relay).
    pub payee_pubkey: PubKeyBytes,
    pub amount: u64,
    pub currency: String,
    /// The nonce the payee issued for this request (kills replay).
    pub nonce: Vec<u8>,
    /// The slot the payment is claimed in (must be an aligned slot in the grant).
    pub slot: u64,
}

/// Builds a linked chain of promises for one payer certificate.
///
/// The builder owns the two pieces of state a payer must not get wrong:
///   * the next `seq` to use (monotonic, never reused);
///   * the `prev_hash` for the next promise (the last built promise's body digest).
///
/// Construct it at whatever point in the payer's history the certificate was issued,
/// then call [`sign_next`](Self::sign_next) once per payment. Each returned promise
/// links to the previous one, so a payee running `verify_promise` with the matching
/// `ChainHead` sees an unbroken chain.
pub struct PromiseBuilder<'a> {
    payer: &'a dyn Signer,
    cert: Certificate,
    next_seq: u64,
    prev_hash: Hash,
}

impl<'a> PromiseBuilder<'a> {
    /// Start a promise chain for `cert`, signed by `payer`.
    ///
    /// `first_seq` is the seq of the first promise this builder will emit — normally
    /// `cert.seq_at_issue + 1`. `genesis_prev_hash` is the `prev_hash` for that first
    /// promise; when there is no prior promise the convention is all-zero.
    pub fn new(
        payer: &'a dyn Signer,
        cert: Certificate,
        first_seq: u64,
        genesis_prev_hash: Hash,
    ) -> Self {
        PromiseBuilder {
            payer,
            cert,
            next_seq: first_seq,
            prev_hash: genesis_prev_hash,
        }
    }

    /// Convenience constructor for a fresh chain: the first promise is
    /// `seq_at_issue + 1` with an all-zero `prev_hash`.
    pub fn fresh(payer: &'a dyn Signer, cert: Certificate) -> Self {
        let first_seq = cert.seq_at_issue + 1;
        Self::new(payer, cert, first_seq, [0u8; 32])
    }

    /// The seq the next [`sign_next`](Self::sign_next) call will use.
    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    /// The `prev_hash` the next promise will carry (the last built promise's body
    /// digest, or the genesis value if none built yet).
    pub fn current_head(&self) -> Hash {
        self.prev_hash
    }

    /// Build, payer-sign, and link the next promise in the chain.
    ///
    /// After this returns, the builder's `seq` has advanced by one and its
    /// `prev_hash` is the new promise's body digest, so the following call links
    /// correctly. The signature is over the canonical body, so the promise verifies
    /// against the certificate's payer key by construction.
    pub fn sign_next(&mut self, payment: PaymentDetails) -> Promise {
        let mut promise = Promise {
            payer_cert: self.cert.clone(),
            payee_pubkey: payment.payee_pubkey,
            amount: payment.amount,
            currency: payment.currency,
            nonce: payment.nonce,
            seq: self.next_seq,
            prev_hash: self.prev_hash,
            slot: payment.slot,
            sig_payer: [0u8; 64],
        };
        promise.sig_payer = self.payer.sign_prehash(&promise.body_digest());

        // Advance the chain state for the next promise.
        self.prev_hash = promise.body_digest();
        self.next_seq += 1;

        promise
    }
}

/// Sign an arbitrary already-built promise body, for callers that manage their own
/// chain state and just need the canonical signing step. Returns the signature; it
/// does NOT mutate the promise, so the caller assigns it to `sig_payer`.
pub fn sign_promise_body(payer: &dyn Signer, promise: &Promise) -> SigBytes {
    payer.sign_prehash(&promise.body_digest())
}

#[cfg(test)]
mod tests {
    // The builder is exercised end-to-end (build -> verify -> chain-link) in
    // `tests/builder.rs`, which has access to the deterministic TestSigner. Unit
    // coverage here is intentionally omitted to avoid duplicating that harness.
}
