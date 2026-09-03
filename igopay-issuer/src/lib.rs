//! igopay-issuer — the issuer's domain logic, as a pure library.
//!
//! Phase 2 of `research/07-build-plan.md`. Like `igopay-core`, this crate has **no
//! network, no database, no HTTP**: it is the decision logic an issuer service wraps,
//! so it can be tested exhaustively before any transport exists.
//!
//! ## Why the issuer exists at all
//!
//! Everything about a promise is verifiable offline by the payee (`igopay-core`), with
//! one exception the protocol cannot close locally (B9): a payer who spends `seq = 12`
//! with payee A and a *different* `seq = 12` with payee B is invisible to each of them
//! alone. `igopay_core::PayeeLedger` catches a double spend only against promises that
//! *same* payee retained. The fork surfaces when the two promises are finally brought
//! together — and that is the issuer's job.
//!
//! So the issuer is not a trusted authority over payments; it is a **rendezvous point
//! for evidence**. It cannot invent a fork, because a fork proof is two promises signed
//! by the payer's own hardware key. It can only notice one.
//!
//! ## Modules
//!
//! * [`registry`] — dedupe on `(payer_pubkey, seq)` and the fork-proof engine. This is
//!   where the cross-payee gap is closed.
//! * [`publish`] — block-list publication (B13): the blocked set compressed into one
//!   signed artefact an offline device installs. Policy only; the wire format and its
//!   validation live in `igopay_core::blocklist` so publisher and phone cannot drift.
//! * [`checkpoint`] — the issuer's append-only log of what it has published (B7), which is
//!   what makes the *issuer* unable to tell two devices two different stories. Same split
//!   as above: `igopay_core::checkpoint` owns the artefact and its rules.
//! * [`anchor`] — the [`anchor::AnchorSink`] seam. A chain makes equivocation provable;
//!   publishing the head where strangers can read it is what makes anyone notice, and
//!   [`anchor::WitnessAnchor`] goes one step further by collecting a second party's
//!   cosignature so an **offline** payee can check it at the counter. `NoOpAnchor`
//!   **cannot** report anchored — the same discipline as `NoOpSettlement` and `Settled`.
//! * [`mirror`] — the log as plain text for a public repository: one line per publication,
//!   so an append is one added line in a diff and a rewrite is visible to anyone reading the
//!   repository's history, cryptography or no cryptography.
//! * [`registration`] — attestation → certificate, and the tiering that sets the caps.
//!   The hardware check is a **binary admission gate**, not a dial: `09` §3 measured
//!   StrongBox absent from the target device class and the attestation chain valid for
//!   only 13 days, so there is neither a distribution to price against nor anything
//!   durable to re-attest. Caps come from fork-free history, KYC and vouching instead,
//!   and [`registration::TieringInputs`] has no attestation field so that decision
//!   cannot quietly erode. Chain verification itself is a seam
//!   ([`registration::AttestationVerifier`]) because `tools/verify_attestation.py` is the
//!   reference implementation and a second one could disagree with it.
//! * [`settlement`] — the [`settlement::SettlementAdapter`] seam. `08` §6 decision 2:
//!   make it an interface from day one so the rail and jurisdiction question stays open.
//!   Only `NoOpSettlement` and `ManualSettlement` exist now; NIP and Sui are later
//!   implementations of the same trait.
//!
//! ## What is deliberately NOT here yet
//!
//! A production [`registration::AttestationVerifier`]. The only implementation in-tree is
//! [`registration::RefusingVerifier`], which admits nobody — the correct default, since an
//! issuer that forgets to wire a real one should register no devices rather than every
//! device. Wiring the real gate means driving the checks
//! `tools/verify_attestation.py` already performs, against Google's pinned roots and
//! status list.

pub mod anchor;
pub mod checkpoint;
pub mod mirror;
pub mod publish;
pub mod registration;
pub mod registry;
pub mod settlement;

pub use anchor::{
    audit_anchored_head, AnchorAudit, AnchorSink, AnchorStatus, ManualAnchor, NoOpAnchor,
    WitnessAnchor,
};
pub use checkpoint::{publish_with_checkpoint, CheckpointLog, CheckpointedPublication, LogError};
pub use publish::{publish_block_list, PublishParams};
pub use registration::{
    decide_grant, inputs_from_registry, register, AttestationRefusal, AttestationVerdict,
    AttestationVerifier, ChallengeBook, ChallengeError, Grant, Guarantor, KycCaps, KycLevel,
    RefusingVerifier, RegistrationRefusal, RegistrationRequest, SecurityLevel, TieringInputs,
    TieringPolicy, VerifiedBoot, MIN_CHALLENGE_LEN,
};
pub use registry::{PromiseRegistry, Submission, SubmitError};
pub use settlement::{ManualSettlement, NoOpSettlement, SettlementAdapter, SettlementStatus};
