//! Offline verification (`07-build-plan.md` §2) and fork detection.
//!
//! Every check here is self-contained (B9): it needs only the pinned issuer public
//! key, the payee's own request parameters, a cached block list, and an injected
//! clock. No network. What the core deliberately CANNOT decide offline — whether the
//! payer has settled elsewhere, or any other global state — is out of scope here and
//! must be surfaced to the merchant as "pending, not settled".

use crate::blocklist::BlockList;
use crate::clock::{Clock, SKEW_TOLERANCE_SECS};
use crate::crypto::{PubKeyBytes, Verifier};
use crate::types::{ForkProof, Hash, PaymentRequest, Promise};

/// The payee's local view of a payer's hash chain: the last promise it accepted
/// from that payer. Kept so the next promise can be linked (`prev_hash`) and its
/// `seq` checked for continuity. A payee that has never seen this payer passes
/// `None` and simply records the head returned in [`Accepted`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    /// `seq` of the last promise accepted from this payer.
    pub seq: u64,
    /// SHA-256 of that promise's signed body — what the *next* promise in the chain
    /// must carry in its `prev_hash`.
    pub body_digest: Hash,
}

/// Everything the payee brings to a verification that is not in the promise itself.
pub struct VerifyContext<'a, V: Verifier, C: Clock> {
    /// The pinned issuer public key. `sig_issuer` on the certificate must verify
    /// against this and nothing else.
    pub issuer_pubkey: &'a PubKeyBytes,
    /// This payee's own public key. The promise must be bound to it (kills relay).
    pub my_pubkey: &'a PubKeyBytes,
    /// The nonce this payee issued for this request (kills replay).
    pub expected_nonce: &'a [u8],
    /// The payee's cached block list (B13).
    pub block_list: &'a BlockList,
    /// The verifier implementation (production: P256Verifier).
    pub verifier: &'a V,
    /// The injected, uptime-anchored clock.
    pub clock: &'a C,
    /// The payee's last-known chain head for this payer, if seen before locally.
    /// Enables the seq-continuity check (`07` §2 check 6) and, when the new promise
    /// is the *immediate* successor, the `prev_hash` linkage check (B2).
    pub known_head: Option<ChainHead>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// `sig_issuer` did not verify against the pinned issuer key.
    BadIssuerSignature,
    /// `sig_payer` did not verify against the certificate's payer key.
    BadPayerSignature,
    /// A signature was well-formed but high-S (malleability). Always rejected.
    MalleableSignature,
    /// Promise was not bound to this payee.
    WrongPayee,
    /// Nonce did not match the one this payee issued.
    WrongNonce,
    /// Amount exceeded the certificate's per-payment cap.
    OverCap,
    /// Slot fell outside the certificate's grant window.
    SlotOutsideGrant,
    /// Slot is in-window but not aligned to the grant's `granularity_secs` boundary
    /// (B10: the grant is a namespace of evenly spaced slots, not free seconds).
    SlotMisaligned {
        from: u64,
        granularity_secs: u64,
        got: u64,
    },
    /// Slot is in the future beyond the skew tolerance.
    SlotInFuture,
    /// The clock could not produce a trusted time (e.g. post-reboot, un-anchored).
    UntrustedClock,
    /// seq did not continue from the last one seen for this payer.
    SeqDiscontinuity { expected_min: u64, got: u64 },
    /// The promise claims to be the immediate successor of the last one we accepted
    /// (`seq == known.seq + 1`) but its `prev_hash` does not link to that promise's
    /// body. The hash chain (B2) is broken — a jump that no honest chain produces.
    PrevHashMismatch { expected: Hash, got: Hash },
    /// The payer is on the block list's **exact** set: certainly blocked, no false
    /// positive possible. Refuse and say so.
    BlockedPayer,
    /// The payer matched the block list's **Bloom filter** but not its exact set, so
    /// this is "probably blocked" — carrying the filter's false-positive rate.
    ///
    /// Kept distinct from [`VerifyError::BlockedPayer`] deliberately. Collapsing the
    /// two would mean a small fraction of honest payers get told they are cheats with
    /// no recourse, which is not a cost the protocol should silently impose on the
    /// people it exists to serve. The payee should decline *this* payment and route
    /// the payer to an online check, not accuse them.
    BlockedPayerProbable,
    /// The certificate's validity window is inverted (`not_after < not_before`) —
    /// a malformed grant the issuer should never sign; always rejected.
    CertWindowInverted { not_before: u64, not_after: u64 },
    /// "Now" is before the certificate's `not_before` — the cert is not yet valid.
    CertNotYetValid { not_before: u64, now: u64 },
    /// "Now" is after the certificate's `not_after` — the cert has expired. This is
    /// how a short-lived certificate self-revokes without an online lookup.
    CertExpired { not_after: u64, now: u64 },
    /// The certificate's slot grant is not contained within its validity window
    /// (`grant.from < not_before` or `grant.to > not_after`). A coherent issuer
    /// never grants slots outside the period the certificate is valid; such a cert
    /// is malformed and rejected structurally, even though issuer-signed.
    GrantOutsideValidity {
        grant_from: u64,
        grant_to: u64,
        not_before: u64,
        not_after: u64,
    },
    /// The promise's amount does not equal the amount this payee requested. Only
    /// checked by [`verify_promise_for_request`]; the payer tried to pay a different
    /// figure than was asked.
    AmountMismatch { requested: u64, got: u64 },
    /// The promise's currency does not match the requested currency. Only checked by
    /// [`verify_promise_for_request`].
    CurrencyMismatch,
}

/// The exposure a payee prices themselves (`07` §2 check 8): how many promises this
/// payer has made since the issuer last saw them. Cannot be understated without
/// forking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exposure {
    pub promises_since_issue: u64,
}

/// A fully accepted promise plus the exposure figure for the payee to price, and
/// the new chain head the payee should persist for this payer so the *next* promise
/// can be linked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accepted {
    pub exposure: Exposure,
    /// The chain head to store for this payer: `(seq, body_digest)` of the promise
    /// just accepted. Feed this back as `known_head` on the next verification.
    pub new_head: ChainHead,
}

/// Run the full offline verification check list against a promise.
///
/// Order matters: signatures first (cheapest way to reject garbage is actually the
/// binding checks, but a valid signature is what makes every other field
/// trustworthy), then the payee-binding and policy checks.
pub fn verify_promise<V: Verifier, C: Clock>(
    promise: &Promise,
    ctx: &VerifyContext<V, C>,
) -> Result<Accepted, VerifyError> {
    let cert = &promise.payer_cert;

    // 1. sig_issuer over the certificate body, against the PINNED issuer key.
    ctx.verifier
        .verify_prehash(ctx.issuer_pubkey, &cert.body_digest(), &cert.sig_issuer)
        .map_err(map_sig_err(VerifyError::BadIssuerSignature))?;

    // 2. sig_payer over the promise body, against the cert's payer key.
    ctx.verifier
        .verify_prehash(
            &cert.payer_pubkey,
            &promise.body_digest(),
            &promise.sig_payer,
        )
        .map_err(map_sig_err(VerifyError::BadPayerSignature))?;

    // 3. Binding: this payee, this nonce.
    if &promise.payee_pubkey != ctx.my_pubkey {
        return Err(VerifyError::WrongPayee);
    }
    if promise.nonce.as_slice() != ctx.expected_nonce {
        return Err(VerifyError::WrongNonce);
    }

    // The anchored "now" is needed both for the certificate validity window and the
    // slot future-check, so resolve it once. Fails closed if the clock is untrusted
    // (e.g. post-reboot, not re-anchored).
    let now = ctx.clock.now_utc().ok_or(VerifyError::UntrustedClock)?;

    // 4. Certificate validity window. A certificate is short-lived by construction:
    //    the issuer signs a `[not_before, not_after]` window, and a payee refuses it
    //    outside that window WITHOUT an online revocation lookup. This is the offline
    //    self-revocation path (B9): a superseded or revoked key simply stops being
    //    accepted once its window closes.
    let cert_nb = cert.not_before;
    let cert_na = cert.not_after;
    if cert_na < cert_nb {
        return Err(VerifyError::CertWindowInverted {
            not_before: cert_nb,
            not_after: cert_na,
        });
    }
    // The slot grant must fall inside the validity window: a coherent issuer never
    // grants slots for a period the certificate is not valid over. Checked against
    // the signed window, so it holds regardless of the current clock.
    let grant = &cert.slot_grant;
    if grant.from < cert_nb || grant.to > cert_na {
        return Err(VerifyError::GrantOutsideValidity {
            grant_from: grant.from,
            grant_to: grant.to,
            not_before: cert_nb,
            not_after: cert_na,
        });
    }
    if now < cert_nb {
        return Err(VerifyError::CertNotYetValid {
            not_before: cert_nb,
            now,
        });
    }
    if now > cert_na {
        return Err(VerifyError::CertExpired {
            not_after: cert_na,
            now,
        });
    }

    // 5. Amount within the certificate's per-payment cap.
    if promise.amount > cert.per_payment_cap {
        return Err(VerifyError::OverCap);
    }

    // 6. Slot within grant, aligned to the grant's granularity, and not in the
    //    future beyond skew tolerance.
    //
    //    B10 treats the grant as a pre-allocated namespace of slots spaced
    //    `granularity_secs` apart starting at `grant.from`. A promise must name one
    //    of those slots, not an arbitrary second inside the window — the spacing is
    //    what makes the grant double as a rate limit (one promise per slot). A slot
    //    that is in-window but off-boundary is malformed.
    if promise.slot < grant.from || promise.slot > grant.to {
        return Err(VerifyError::SlotOutsideGrant);
    }
    if grant.granularity_secs == 0
        || !(promise.slot - grant.from).is_multiple_of(grant.granularity_secs)
    {
        return Err(VerifyError::SlotMisaligned {
            from: grant.from,
            granularity_secs: grant.granularity_secs,
            got: promise.slot,
        });
    }
    if promise.slot > now.saturating_add(SKEW_TOLERANCE_SECS) {
        return Err(VerifyError::SlotInFuture);
    }

    // 7. Chain continuity (B2), if this payer is already known locally.
    //
    //    Two linked checks against the payee's stored chain head:
    //      (a) seq must strictly advance — a promise must never reuse or fall below
    //          a seq we have already accepted from this payer.
    //      (b) if this promise is the IMMEDIATE successor (seq == head.seq + 1), its
    //          prev_hash must equal the stored head's body digest. This is the hash
    //          link that makes the chain a chain: a payer who skips or rewrites
    //          history cannot produce a matching prev_hash without forking.
    //
    //    When seq jumps by more than one (a gap — promises made to other payees we
    //    never saw), we cannot check the intervening link offline, so prev_hash is
    //    not asserted here; the gap itself is visible via exposure (check 8) and the
    //    seq-continuity floor still holds.
    if let Some(head) = ctx.known_head {
        if promise.seq <= head.seq {
            return Err(VerifyError::SeqDiscontinuity {
                expected_min: head.seq + 1,
                got: promise.seq,
            });
        }
        if promise.seq == head.seq + 1 && promise.prev_hash != head.body_digest {
            return Err(VerifyError::PrevHashMismatch {
                expected: head.body_digest,
                got: promise.prev_hash,
            });
        }
    }

    // 8. Block list (B13). The exact set and the filter are reported separately: a
    //    filter-only hit is "probably blocked" and must not be presented to a payer as
    //    a finding of fraud.
    if ctx.block_list.contains_exact(promise.payer_pubkey()) {
        return Err(VerifyError::BlockedPayer);
    }
    if ctx.block_list.contains_in_filter(promise.payer_pubkey()) {
        return Err(VerifyError::BlockedPayerProbable);
    }

    // 9. Exposure disclosure. The payer cannot understate seq without forking, so
    //    (seq - seq_at_issue) is a floor on promises made since issuer contact.
    let promises_since_issue = promise.seq.saturating_sub(cert.seq_at_issue);

    Ok(Accepted {
        exposure: Exposure {
            promises_since_issue,
        },
        new_head: ChainHead {
            seq: promise.seq,
            body_digest: promise.body_digest(),
        },
    })
}

fn map_sig_err(on_fail: VerifyError) -> impl Fn(crate::crypto::CryptoError) -> VerifyError {
    move |e| match e {
        crate::crypto::CryptoError::HighS => VerifyError::MalleableSignature,
        _ => on_fail.clone(),
    }
}

// ---------------------------------------------------------------------------
// Fork detection
// ---------------------------------------------------------------------------

/// Attempt to construct a fork proof from two promises. A fork exists iff the two
/// promises share a payer and a `seq` but have different signed bodies. The result
/// is undeniable because each promise carries the payer's own signature.
///
/// Returns `None` when the pair is NOT a fork: different payers, different seq, or
/// genuinely identical bodies (a mere duplicate, not a double spend).
pub fn detect_fork(a: &Promise, b: &Promise) -> Option<ForkProof> {
    if a.payer_pubkey() != b.payer_pubkey() {
        return None;
    }
    if a.seq != b.seq {
        return None;
    }
    if a.body_digest() == b.body_digest() {
        // Same seq, same body: a replayed duplicate, not a fork.
        return None;
    }
    Some(ForkProof {
        a: a.clone(),
        b: b.clone(),
    })
}

/// Independently verify that a claimed fork proof is genuine: same payer, same seq,
/// different bodies, and BOTH signatures valid under the payer's key. This is what a
/// third party (issuer, another payee) runs to confirm a fork before acting on it,
/// so that a fabricated "proof" with an invalid signature is rejected.
pub fn verify_fork_proof<V: Verifier>(proof: &ForkProof, verifier: &V) -> bool {
    let a = &proof.a;
    let b = &proof.b;
    if a.payer_pubkey() != b.payer_pubkey() {
        return false;
    }
    if a.seq != b.seq {
        return false;
    }
    if a.body_digest() == b.body_digest() {
        return false;
    }
    let key = a.payer_pubkey();
    verifier
        .verify_prehash(key, &a.body_digest(), &a.sig_payer)
        .is_ok()
        && verifier
            .verify_prehash(key, &b.body_digest(), &b.sig_payer)
            .is_ok()
}

// ---------------------------------------------------------------------------
// Payee request flow
// ---------------------------------------------------------------------------

/// Verify a scanned promise **against the payment request this payee issued**.
///
/// This is the payee-side convenience over [`verify_promise`]: it takes the
/// [`PaymentRequest`] the payee generated (whose `payee_pubkey` and `nonce` are the
/// binding parameters) and threads them into a [`VerifyContext`], so the caller
/// cannot accidentally verify against a different key or a stale nonce. It also
/// enforces that the promise's **amount and currency match what was requested** —
/// `verify_promise` only checks the amount is within the certificate cap, not that
/// it equals what this payee actually asked for.
///
/// The other context pieces (pinned issuer key, block list, verifier, clock,
/// known chain head) are passed in as usual, because they are payee state, not part
/// of the request.
#[allow(clippy::too_many_arguments)]
pub fn verify_promise_for_request<V: Verifier, C: Clock>(
    promise: &Promise,
    request: &PaymentRequest,
    issuer_pubkey: &PubKeyBytes,
    block_list: &BlockList,
    verifier: &V,
    clock: &C,
    known_head: Option<ChainHead>,
) -> Result<Accepted, VerifyError> {
    // The requested amount/currency must match the promise. Checked before the full
    // verification so a payer trying to pay a different amount than requested is
    // rejected with a clear reason rather than silently accepted at cert-cap level.
    if promise.amount != request.amount {
        return Err(VerifyError::AmountMismatch {
            requested: request.amount,
            got: promise.amount,
        });
    }
    if promise.currency != request.currency {
        return Err(VerifyError::CurrencyMismatch);
    }

    let ctx = VerifyContext {
        issuer_pubkey,
        my_pubkey: &request.payee_pubkey,
        expected_nonce: &request.nonce,
        block_list,
        verifier,
        clock,
        known_head,
    };
    verify_promise(promise, &ctx)
}
