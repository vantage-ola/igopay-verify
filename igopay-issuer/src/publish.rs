//! Block-list publication (B13): turn the registry's blocked-payer set into one signed,
//! compact artefact an offline device can install.
//!
//! The wire format and every validation rule live in `igopay_core::blocklist`, not here.
//! This module is only *policy* — how big to make the filter, how many payers get the
//! exact treatment, how long a list stays fresh. The publisher and the phone must agree
//! on geometry and hash positions byte-for-byte, so there is exactly one implementation
//! of that, shared.
//!
//! ## The one piece of state a caller must keep
//!
//! `epoch`. A device refuses any list whose epoch is not strictly greater than the one it
//! already holds, which is what stops an attacker replaying an old list to un-block a
//! payer who has since been caught. The registry cannot infer the epoch — it does not
//! know what has been published before — so the service must persist a monotonic counter
//! and pass the next value in. Reusing an epoch produces a list every up-to-date device
//! will reject.

use igopay_core::crypto::Signer;
use igopay_core::{BlockList, SignedBlockList, MAX_EXACT_RECENT};

use crate::registry::PromiseRegistry;

/// Publication policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishParams {
    /// Monotonic publication counter. Must exceed every epoch published before.
    pub epoch: u64,
    /// UTC seconds at publication.
    pub issued_at: u64,
    /// How long before the list is considered stale. Staleness tightens a payee's
    /// offline limits; it never voids the entries (`igopay_core::blocklist`).
    pub valid_for_secs: u64,
    /// Filter bits per blocked payer. 12 gives roughly a 0.3% false-positive rate at
    /// 8 hash probes; see `igopay_core::hashes_for_bits_per_item`.
    pub bits_per_item: usize,
    /// Filter floor. At small entry counts the standard Bloom sizing is optimistic —
    /// with only a handful of items the probes collide across a tiny bit array and the
    /// real false-positive rate is far worse than the nominal one. 512 bits is 64 bytes,
    /// which costs nothing to distribute.
    pub min_filter_bits: usize,
    /// How many of the most recently blocked payers go in the exact set, where there is
    /// no false-positive possibility. Clamped to `MAX_EXACT_RECENT`, above which no
    /// device would accept the list.
    pub exact_recent: usize,
}

impl PublishParams {
    /// Defaults: 24-hour freshness, 12 bits per payer, 512-bit floor, 256 exact entries.
    pub fn new(epoch: u64, issued_at: u64) -> Self {
        PublishParams {
            epoch,
            issued_at,
            valid_for_secs: 24 * 60 * 60,
            bits_per_item: 12,
            min_filter_bits: 512,
            exact_recent: 256,
        }
    }
}

/// Build and sign a block list covering every payer the registry has blocked.
///
/// Every blocked payer goes into the Bloom filter, *including* the ones that also go in
/// the exact set. That redundancy costs a few bits and buys a simpler invariant: the
/// filter alone is a complete answer, so a consumer that ignores the exact set is still
/// correct, and a payer dropping out of the exact window in a later publication is never
/// a moment where they stop being blocked.
///
/// The exact set is filled from the *most recently* blocked end, because the freshest bad
/// actors are the ones still actively spending, and they are the ones a payee should be
/// certain about rather than merely suspicious of.
pub fn publish_block_list<S: Signer>(
    registry: &PromiseRegistry,
    params: &PublishParams,
    signer: &S,
) -> SignedBlockList {
    let blocked = registry.blocked_in_block_order(); // oldest first
    let bits_per_item = params.bits_per_item.max(1);
    let sized = blocked.len().saturating_mul(bits_per_item);
    let num_bits = sized.max(params.min_filter_bits);

    let mut list = BlockList::new(
        num_bits,
        igopay_core::hashes_for_bits_per_item(bits_per_item),
    );
    for payer in &blocked {
        list.insert(payer);
    }

    let exact = params.exact_recent.min(MAX_EXACT_RECENT);
    let start = blocked.len().saturating_sub(exact);
    for payer in &blocked[start..] {
        list.insert_recent(*payer);
    }

    let not_after = params.issued_at.saturating_add(params.valid_for_secs);
    let mut doc = list.to_unsigned(params.epoch, params.issued_at, not_after);
    doc.sig_issuer = signer.sign_prehash(&doc.body_digest());
    doc
}
