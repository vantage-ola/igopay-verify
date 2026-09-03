//! Cryptographic boundary of the core.
//!
//! D5: the curve is ECDSA P-256 (secp256r1), because the iOS Secure Enclave holds
//! P-256 keys only and Android Keystore supports it. Signatures are the raw fixed
//! 64-byte `r‖s` form — never DER — so a promise's signature field is a constant
//! size and a decoder gets no variable-length wrapping to disagree over.
//!
//! Malleability is the sharp edge. For any valid ECDSA signature `(r, s)`, the pair
//! `(r, n - s)` verifies equally well. Under this protocol that is a forgery vector:
//! a fork proof is "two signed promises with equal `seq` and different bodies", so a
//! malleated copy of one honest promise could masquerade as evidence of a double
//! spend the payer never committed. Ed25519 would have given non-malleability for
//! free; with P-256 it is an explicit invariant enforced in TWO places:
//!
//!   * signing side (platform): canonicalize to low-S before returning `r‖s`;
//!   * verifying side (here): REJECT any signature whose `s > n/2`.
//!
//! The core never holds a private key. Signing is the platform's job behind the
//! [`Signer`] trait (Android Keystore / iOS Secure Enclave); the core only ever
//! verifies.

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::elliptic_curve::scalar::IsHigh;

/// A 33-byte SEC1 compressed P-256 public key. Compressed to keep promises small.
pub type PubKeyBytes = [u8; 33];

/// A raw `r‖s` P-256 signature: 32-byte r followed by 32-byte s.
pub type SigBytes = [u8; 64];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    BadPublicKey,
    BadSignatureEncoding,
    /// `s` was in the upper half of the curve order. Rejected to prevent
    /// signature-malleability fork-proof forgery. See module docs.
    HighS,
    VerificationFailed,
}

/// Signing lives OUTSIDE the core. The platform implements this over a
/// hardware-backed key that the core can never read.
///
/// Implementations MUST return a low-S canonical `r‖s` signature. The core will
/// reject high-S signatures on verify, so a non-canonicalizing signer would
/// produce promises the core refuses to accept.
pub trait Signer {
    /// Sign an already-hashed 32-byte digest, returning raw `r‖s`.
    fn sign_prehash(&self, digest: &[u8; 32]) -> SigBytes;

    /// The SEC1-compressed public key corresponding to this signer.
    fn public_key(&self) -> PubKeyBytes;
}

/// Verification is pure and lives in the core; it runs on any platform.
pub trait Verifier {
    fn verify_prehash(
        &self,
        pubkey: &PubKeyBytes,
        digest: &[u8; 32],
        sig: &SigBytes,
    ) -> Result<(), CryptoError>;
}

/// The stock P-256 verifier used everywhere in production.
#[derive(Debug, Default, Clone, Copy)]
pub struct P256Verifier;

impl Verifier for P256Verifier {
    fn verify_prehash(
        &self,
        pubkey: &PubKeyBytes,
        digest: &[u8; 32],
        sig: &SigBytes,
    ) -> Result<(), CryptoError> {
        verify_p256_low_s(pubkey, digest, sig)
    }
}

/// Verify a raw `r‖s` P-256 signature over a 32-byte prehash, rejecting high-S.
pub fn verify_p256_low_s(
    pubkey: &PubKeyBytes,
    digest: &[u8; 32],
    sig: &SigBytes,
) -> Result<(), CryptoError> {
    let vk = VerifyingKey::from_sec1_bytes(pubkey).map_err(|_| CryptoError::BadPublicKey)?;
    let signature = Signature::from_slice(sig).map_err(|_| CryptoError::BadSignatureEncoding)?;

    // Reject high-S BEFORE checking the math. A malleated (r, n-s) copy verifies
    // fine cryptographically; we forbid it structurally.
    if signature.s().is_high().into() {
        return Err(CryptoError::HighS);
    }

    vk.verify_prehash(digest, &signature)
        .map_err(|_| CryptoError::VerificationFailed)
}
