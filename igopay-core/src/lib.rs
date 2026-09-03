//! igopay-core — the offline payment-promise protocol, as a pure library.
//!
//! Scope and non-scope (see `research/07-build-plan.md` §2, and `09` §6 for the
//! language/curve rationale):
//!
//! * The core does CBOR codec, verification, the hash chain, fork proofs, slot
//!   validation, the block list, and the issuer's checkpoint chain.
//! * The core NEVER holds a private key. Signing is a platform trait
//!   ([`crypto::Signer`]) implemented over Android Keystore or the iOS Secure
//!   Enclave; the core only verifies.
//! * Time is an injected [`clock::Clock`] (uptime-anchored), never the system
//!   wall clock.
//!
//! Consensus-critical invariants, in one place so they are auditable:
//!   1. Canonical CBOR (`codec`): same logical value ⇒ same bytes, always. Decoders
//!      reject non-canonical input.
//!   2. ECDSA P-256, raw `r‖s`, low-S only. High-S signatures are rejected on verify
//!      to prevent malleability-based fork-proof forgery (`crypto`).
//!   3. Promise identity for fork detection is the SHA-256 of the signed body
//!      (`types`, `verify`). The same rule gives a block list and a checkpoint their
//!      identity, so a re-signed but unchanged artefact is never mistaken for a
//!      second, conflicting one (`blocklist`, `checkpoint`).
//!
//! ## Both sides are held to the same standard
//!
//! A payer who spends twice at one `seq` is caught by their own signatures
//! ([`ForkProof`]). An issuer that publishes two histories at one log position is
//! caught by its own signatures ([`checkpoint::EquivocationProof`]). Neither needs a
//! trusted party to adjudicate — which is what lets this system be audited by the
//! people it affects rather than only by whoever runs it.
//!
//! ## `no_std`
//!
//! The crate is `#![no_std]` and depends only on `alloc` (for `Vec`, `String`,
//! `BTreeSet`), so it can be linked into constrained builds and the mobile FFI
//! layer without dragging in the full standard library. Tests link `std` as usual.

#![no_std]

extern crate alloc;

#[cfg(test)]
extern crate std;

pub mod blocklist;
pub mod build;
pub mod checkpoint;
pub mod clock;
pub mod codec;
pub mod crypto;
pub mod hex;
pub mod ledger;
pub mod qr;
pub mod types;
pub mod verify;
pub mod witness;

pub use blocklist::{
    hashes_for_bits_per_item, BlockList, BlockListError, InstalledBlockList, SignedBlockList,
    MAX_EXACT_RECENT, MAX_FILTER_BYTES, MAX_HASHES,
};
pub use build::{build_certificate, sign_promise_body, PaymentDetails, PromiseBuilder};
pub use checkpoint::{
    classify_checkpoint, detect_equivocation, install_checkpointed_list, verify_chain_link,
    verify_checkpoint, verify_equivocation_proof, verify_list_commitment, Checkpoint,
    CheckpointError, CheckpointTracker, CheckpointVerdict, EquivocationKind, EquivocationProof,
    GENESIS_PREV,
};
pub use clock::{Clock, FixedClock, UptimeAnchoredClock, SKEW_TOLERANCE_SECS};
pub use crypto::{
    verify_p256_low_s, CryptoError, P256Verifier, PubKeyBytes, SigBytes, Signer, Verifier,
};
pub use hex::{from_hex, hex_lines, render_lines, to_hex};
pub use ledger::{PayeeLedger, PayerRecord};
pub use qr::{from_qr_payload, to_qr_payload, QrError};
pub use types::{Certificate, DecodeError, ForkProof, Hash, PaymentRequest, Promise, SlotGrant};
pub use verify::{
    detect_fork, verify_fork_proof, verify_promise, verify_promise_for_request, Accepted,
    ChainHead, Exposure, VerifyContext, VerifyError,
};
pub use witness::{
    install_witnessed_list, verify_witnessed, Cosignature, WitnessCoverage, WitnessLog,
    WitnessRefusal, WitnessedCheckpoint, COSIGN_DOMAIN, MAX_COSIGNATURES,
};
