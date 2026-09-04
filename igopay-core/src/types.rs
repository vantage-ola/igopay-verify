//! Protocol data types and their canonical wire encoding.
//!
//! Three signed artefacts, exactly as `07-build-plan.md` §2 specifies:
//!   * [`Certificate`] — issued online, cached, short-lived; signed by the issuer.
//!   * [`Promise`]      — signed offline, one message, one hop; signed by the payer.
//!   * [`ForkProof`]    — two promises, equal `seq`, different bodies, one payer.
//!
//! Plus one unsigned artefact:
//!   * [`PaymentRequest`] — the payee-side QR the payer scans first (`07` §3). It
//!     carries no value and is not signed; it just hands the payer the payee key,
//!     amount and fresh nonce the resulting promise must bind to.
//!
//! Every type encodes as a canonical CBOR map with small ascending integer keys
//! (see [`crate::codec`]). The "body" of a signed type is its encoding with the
//! signature field omitted; that body is what gets hashed and signed. Decoders are
//! strict: unknown keys, wrong types, out-of-order keys and non-canonical integers
//! are all rejected, because leniency would reopen the malleability the canonical
//! form exists to close.

use crate::codec::{CodecError, Decoder, Encoder};
use crate::crypto::{PubKeyBytes, SigBytes};
use alloc::string::String;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    Codec(CodecError),
    MissingField(u64),
    UnexpectedField(u64),
    WrongArrayLen,
}

impl From<CodecError> for DecodeError {
    fn from(e: CodecError) -> Self {
        DecodeError::Codec(e)
    }
}

// ---------------------------------------------------------------------------
// SlotGrant (B10): the pre-allocated time namespace granted by the issuer.
// keys: 0=from, 1=to, 2=granularity_secs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotGrant {
    pub from: u64,
    pub to: u64,
    pub granularity_secs: u64,
}

impl SlotGrant {
    /// The slot a payment made at `now` belongs to, or `None` when `now` falls outside
    /// this grant or the grant names no slots at all.
    ///
    /// **The slot lattice is anchored to `from`, not to the wall clock.** The valid slots
    /// are `from`, `from + granularity_secs`, `from + 2*granularity_secs`, … up to `to`.
    /// The issuer sets `from` to the second it issued the certificate (see `decide_grant`
    /// in `igopay-issuer`), so that lattice sits at an arbitrary offset that differs per
    /// payer and moves on every certificate refresh.
    ///
    /// The consequence is a trap, and it caught the first real caller of this crate. The
    /// obvious way to name "the current hour" — `now / granularity * granularity` — floors
    /// to a *clock* boundary, which lands below `from` and is refused by every payee with
    /// `SlotOutsideGrant`, or lands off-lattice and is refused with `SlotMisaligned`. It
    /// is wrong in a way that looks right, is invisible until a payee runs the check, and
    /// no amount of documentation would have prevented it: `tools/ffi-probe` was written
    /// against the doc comments and still got it wrong. So the derivation is a function
    /// here rather than a rule callers are asked to reimplement.
    ///
    /// Guarantee: a slot returned by this method passes *every* slot check in
    /// [`crate::verify::verify_promise`] evaluated at the same `now` — in-window, aligned,
    /// and never future-dated. There is no input for which this hands back a slot the
    /// verifier then refuses.
    pub fn slot_at(&self, now: u64) -> Option<u64> {
        // A zero granularity names no slots — `verify_promise` refuses such a grant
        // outright — so there is no honest answer to give. An empty or inverted window
        // (`to < from`) falls out of the same two bounds checks.
        if self.granularity_secs == 0 || now < self.from || now > self.to {
            return None;
        }
        // Floor onto the lattice anchored at `from`. `now >= from` here, so the
        // subtraction cannot wrap, and the result is `<= now`, so a slot from this
        // method can never trip the future-dating check either.
        let elapsed = now - self.from;
        Some(self.from + (elapsed / self.granularity_secs) * self.granularity_secs)
    }

    fn encode(&self, e: &mut Encoder) {
        e.map_head(3);
        e.map_key(0);
        e.u64(self.from);
        e.map_key(1);
        e.u64(self.to);
        e.map_key(2);
        e.u64(self.granularity_secs);
    }

    fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 3 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut from = None;
        let mut to = None;
        let mut gran = None;
        for _ in 0..3 {
            match d.map_key(&mut last)? {
                0 => from = Some(d.u64()?),
                1 => to = Some(d.u64()?),
                2 => gran = Some(d.u64()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(SlotGrant {
            from: from.ok_or(DecodeError::MissingField(0))?,
            to: to.ok_or(DecodeError::MissingField(1))?,
            granularity_secs: gran.ok_or(DecodeError::MissingField(2))?,
        })
    }
}

// ---------------------------------------------------------------------------
// Certificate. keys:
// 0=payer_pubkey, 1=handle, 2=tier, 3=per_payment_cap,
// 4=slot_grant, 5=seq_at_issue, 6=not_before, 7=not_after, 8=sig_issuer
// The signed body is keys 0..=7 (everything except sig_issuer).
//
// `not_before`/`not_after` are a UTC-second validity window the ISSUER signs, so a
// certificate is short-lived by construction: a revoked or superseded payer key
// stops being accepted once the window closes, without every payee needing an
// online revocation lookup. The verifier checks the window against the anchored
// clock (never the wall clock — see `clock`).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub payer_pubkey: PubKeyBytes,
    pub handle: String,
    pub tier: u64,
    pub per_payment_cap: u64,
    pub slot_grant: SlotGrant,
    pub seq_at_issue: u64,
    /// First UTC second at which this certificate is valid (inclusive).
    pub not_before: u64,
    /// Last UTC second at which this certificate is valid (inclusive). Must be
    /// `>= not_before`; a verifier rejects an inverted window.
    pub not_after: u64,
    pub sig_issuer: SigBytes,
}

impl Certificate {
    /// Encode the signed body (keys 0..=7). This is what the issuer signs and what
    /// the verifier hashes to check `sig_issuer`.
    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map_head(8);
        e.map_key(0);
        e.bytes(&self.payer_pubkey);
        e.map_key(1);
        e.text(&self.handle);
        e.map_key(2);
        e.u64(self.tier);
        e.map_key(3);
        e.u64(self.per_payment_cap);
        e.map_key(4);
        self.slot_grant.encode(&mut e);
        e.map_key(5);
        e.u64(self.seq_at_issue);
        e.map_key(6);
        e.u64(self.not_before);
        e.map_key(7);
        e.u64(self.not_after);
        e.into_bytes()
    }

    pub fn body_digest(&self) -> Hash {
        Sha256::digest(self.encode_body()).into()
    }

    /// Full encoding including the issuer signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map_head(9);
        e.map_key(0);
        e.bytes(&self.payer_pubkey);
        e.map_key(1);
        e.text(&self.handle);
        e.map_key(2);
        e.u64(self.tier);
        e.map_key(3);
        e.u64(self.per_payment_cap);
        e.map_key(4);
        self.slot_grant.encode(&mut e);
        e.map_key(5);
        e.u64(self.seq_at_issue);
        e.map_key(6);
        e.u64(self.not_before);
        e.map_key(7);
        e.u64(self.not_after);
        e.map_key(8);
        e.bytes(&self.sig_issuer);
        e.into_bytes()
    }

    fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 9 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut payer_pubkey = None;
        let mut handle = None;
        let mut tier = None;
        let mut cap = None;
        let mut grant = None;
        let mut seq_at_issue = None;
        let mut not_before = None;
        let mut not_after = None;
        let mut sig = None;
        for _ in 0..9 {
            match d.map_key(&mut last)? {
                0 => payer_pubkey = Some(d.bytes_fixed::<33>()?),
                1 => handle = Some(d.text()?),
                2 => tier = Some(d.u64()?),
                3 => cap = Some(d.u64()?),
                4 => grant = Some(SlotGrant::decode(d)?),
                5 => seq_at_issue = Some(d.u64()?),
                6 => not_before = Some(d.u64()?),
                7 => not_after = Some(d.u64()?),
                8 => sig = Some(d.bytes_fixed::<64>()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(Certificate {
            payer_pubkey: payer_pubkey.ok_or(DecodeError::MissingField(0))?,
            handle: handle.ok_or(DecodeError::MissingField(1))?,
            tier: tier.ok_or(DecodeError::MissingField(2))?,
            per_payment_cap: cap.ok_or(DecodeError::MissingField(3))?,
            slot_grant: grant.ok_or(DecodeError::MissingField(4))?,
            seq_at_issue: seq_at_issue.ok_or(DecodeError::MissingField(5))?,
            not_before: not_before.ok_or(DecodeError::MissingField(6))?,
            not_after: not_after.ok_or(DecodeError::MissingField(7))?,
            sig_issuer: sig.ok_or(DecodeError::MissingField(8))?,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let c = Self::decode(&mut d)?;
        d.finish()?;
        Ok(c)
    }
}

// ---------------------------------------------------------------------------
// Promise. keys:
// 0=payer_cert, 1=payee_pubkey, 2=amount, 3=currency, 4=nonce,
// 5=seq, 6=prev_hash, 7=slot, 8=sig_payer
// The signed body is keys 0..=7 (everything except sig_payer).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promise {
    pub payer_cert: Certificate,
    pub payee_pubkey: PubKeyBytes,
    pub amount: u64,
    pub currency: String,
    pub nonce: Vec<u8>,
    pub seq: u64,
    pub prev_hash: Hash,
    pub slot: u64,
    pub sig_payer: SigBytes,
}

impl Promise {
    fn encode_common(&self, e: &mut Encoder, include_sig: bool) {
        e.map_head(if include_sig { 9 } else { 8 });
        e.map_key(0);
        // The certificate is embedded verbatim (D2). Its own encoding is already
        // canonical, so it is appended byte-for-byte as this map value.
        let cert = self.payer_cert.encode();
        e.raw(&cert);
        e.map_key(1);
        e.bytes(&self.payee_pubkey);
        e.map_key(2);
        e.u64(self.amount);
        e.map_key(3);
        e.text(&self.currency);
        e.map_key(4);
        e.bytes(&self.nonce);
        e.map_key(5);
        e.u64(self.seq);
        e.map_key(6);
        e.bytes(&self.prev_hash);
        e.map_key(7);
        e.u64(self.slot);
        if include_sig {
            e.map_key(8);
            e.bytes(&self.sig_payer);
        }
    }

    /// Encode the signed body (keys 0..=7). Hashed to check `sig_payer`, and it is
    /// this body's digest that defines promise identity for fork detection.
    pub fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, false);
        e.into_bytes()
    }

    pub fn body_digest(&self) -> Hash {
        Sha256::digest(self.encode_body()).into()
    }

    /// Full encoding including the payer signature. This is what rides in the QR.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        self.encode_common(&mut e, true);
        e.into_bytes()
    }

    fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 9 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut cert = None;
        let mut payee = None;
        let mut amount = None;
        let mut currency = None;
        let mut nonce = None;
        let mut seq = None;
        let mut prev = None;
        let mut slot = None;
        let mut sig = None;
        for _ in 0..9 {
            match d.map_key(&mut last)? {
                0 => cert = Some(Certificate::decode(d)?),
                1 => payee = Some(d.bytes_fixed::<33>()?),
                2 => amount = Some(d.u64()?),
                3 => currency = Some(d.text()?),
                4 => nonce = Some(d.bytes()?),
                5 => seq = Some(d.u64()?),
                6 => prev = Some(d.bytes_fixed::<32>()?),
                7 => slot = Some(d.u64()?),
                8 => sig = Some(d.bytes_fixed::<64>()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(Promise {
            payer_cert: cert.ok_or(DecodeError::MissingField(0))?,
            payee_pubkey: payee.ok_or(DecodeError::MissingField(1))?,
            amount: amount.ok_or(DecodeError::MissingField(2))?,
            currency: currency.ok_or(DecodeError::MissingField(3))?,
            nonce: nonce.ok_or(DecodeError::MissingField(4))?,
            seq: seq.ok_or(DecodeError::MissingField(5))?,
            prev_hash: prev.ok_or(DecodeError::MissingField(6))?,
            slot: slot.ok_or(DecodeError::MissingField(7))?,
            sig_payer: sig.ok_or(DecodeError::MissingField(8))?,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let p = Self::decode(&mut d)?;
        d.finish()?;
        Ok(p)
    }

    /// The payer whose hardware key signed this promise (SEC1-compressed pubkey).
    pub fn payer_pubkey(&self) -> &PubKeyBytes {
        &self.payer_cert.payer_pubkey
    }
}

// ---------------------------------------------------------------------------
// ForkProof: two promises signed by the same payer with equal seq but different
// bodies. Not an accusation — a signature the payer cannot deny. It is portable
// evidence (B8), so it must serialize to hand to the issuer or another payee.
// Encoded as a 2-element array [promise_a, promise_b].
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForkProof {
    pub a: Promise,
    pub b: Promise,
}

impl ForkProof {
    /// Encode as a canonical 2-element array of the two full promises.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.array_head(2);
        // Each promise's own encoding is already canonical; append verbatim.
        e.raw(&self.a.encode());
        e.raw(&self.b.encode());
        e.into_bytes()
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let n = d.array_head()?;
        if n != 2 {
            return Err(DecodeError::WrongArrayLen);
        }
        let a = Promise::decode(&mut d)?;
        let b = Promise::decode(&mut d)?;
        d.finish()?;
        Ok(ForkProof { a, b })
    }
}

// ---------------------------------------------------------------------------
// PaymentRequest: the payee-side artefact the PAYER scans first (`07` §3). It is
// NOT signed — it carries no value and commits the payee to nothing; its whole job
// is to hand the payer the three things a promise must be bound to:
//   * the payee's public key (so the promise binds to this payee — kills relay);
//   * a fresh nonce the payee just generated (so the promise can't be replayed);
//   * the amount/currency the payee is asking for (shown on the payer's confirm
//     screen, and what the payee then checks the returned promise against).
// keys: 0=payee_pubkey, 1=amount, 2=currency, 3=nonce
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaymentRequest {
    pub payee_pubkey: PubKeyBytes,
    pub amount: u64,
    pub currency: String,
    /// A fresh, payee-generated nonce. The core is `no_std` and holds no RNG, so the
    /// platform supplies this from a secure source; the request only carries it.
    pub nonce: Vec<u8>,
}

impl PaymentRequest {
    /// Encode as a canonical CBOR map. Unsigned: there is no body/signature split.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new();
        e.map_head(4);
        e.map_key(0);
        e.bytes(&self.payee_pubkey);
        e.map_key(1);
        e.u64(self.amount);
        e.map_key(2);
        e.text(&self.currency);
        e.map_key(3);
        e.bytes(&self.nonce);
        e.into_bytes()
    }

    fn decode(d: &mut Decoder) -> Result<Self, DecodeError> {
        let n = d.map_head()?;
        if n != 4 {
            return Err(DecodeError::WrongArrayLen);
        }
        let mut last = None;
        let mut payee = None;
        let mut amount = None;
        let mut currency = None;
        let mut nonce = None;
        for _ in 0..4 {
            match d.map_key(&mut last)? {
                0 => payee = Some(d.bytes_fixed::<33>()?),
                1 => amount = Some(d.u64()?),
                2 => currency = Some(d.text()?),
                3 => nonce = Some(d.bytes()?),
                k => return Err(DecodeError::UnexpectedField(k)),
            }
        }
        Ok(PaymentRequest {
            payee_pubkey: payee.ok_or(DecodeError::MissingField(0))?,
            amount: amount.ok_or(DecodeError::MissingField(1))?,
            currency: currency.ok_or(DecodeError::MissingField(2))?,
            nonce: nonce.ok_or(DecodeError::MissingField(3))?,
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, DecodeError> {
        let mut d = Decoder::new(data);
        let r = Self::decode(&mut d)?;
        d.finish()?;
        Ok(r)
    }
}

#[cfg(test)]
mod tests {
    use super::SlotGrant;

    // A grant anchored at a second that is deliberately NOT a round number, because
    // that is what the issuer produces: `from` is whatever second registration
    // happened on. 1000 s of granularity keeps the arithmetic readable.
    fn grant() -> SlotGrant {
        SlotGrant {
            from: 1_757_000_123,
            to: 1_757_000_123 + 10_000,
            granularity_secs: 1_000,
        }
    }

    #[test]
    fn the_first_slot_is_the_anchor_itself() {
        let g = grant();
        // At the instant of issue, and anywhere in the first period, the slot is `from`.
        assert_eq!(g.slot_at(g.from), Some(g.from));
        assert_eq!(g.slot_at(g.from + 1), Some(g.from));
        assert_eq!(g.slot_at(g.from + 999), Some(g.from));
    }

    #[test]
    fn slots_advance_on_the_anchored_lattice_not_the_clock() {
        let g = grant();
        assert_eq!(g.slot_at(g.from + 1_000), Some(g.from + 1_000));
        assert_eq!(g.slot_at(g.from + 1_999), Some(g.from + 1_000));
        assert_eq!(g.slot_at(g.from + 2_000), Some(g.from + 2_000));
    }

    #[test]
    fn flooring_to_a_clock_boundary_fails_in_both_directions() {
        // The claim in the doc comment, made concrete. `from` is not a round number, so
        // `now / granularity * granularity` disagrees with the lattice, and it does so in
        // two distinct ways with two distinct verifier errors.
        let g = grant();

        // In the FIRST period — a payer who registers and pays within the same period,
        // which is exactly what `tools/ffi-probe` did — the clock floor lands BELOW the
        // anchor. The verifier answers `SlotOutsideGrant`.
        let early = g.from + 500;
        let floored_early = early / 1_000 * 1_000;
        assert!(floored_early < g.from);
        assert_eq!(g.slot_at(early), Some(g.from));

        // Later in the grant the clock floor is inside the window but off-lattice, and
        // the verifier answers `SlotMisaligned` instead.
        let later = g.from + 1_500;
        let floored_later = later / 1_000 * 1_000;
        assert!(floored_later > g.from && floored_later < g.to);
        assert_ne!((floored_later - g.from) % 1_000, 0);
        assert_eq!(g.slot_at(later), Some(g.from + 1_000));
    }

    #[test]
    fn outside_the_window_there_is_no_slot() {
        let g = grant();
        assert_eq!(g.slot_at(g.from - 1), None);
        assert_eq!(g.slot_at(g.to + 1), None);
        // The final instant is still in the grant, and floors into the last full period.
        assert_eq!(g.slot_at(g.to), Some(g.from + 10_000));
    }

    #[test]
    fn a_grant_that_names_no_slots_yields_none() {
        // Zero granularity: `verify_promise` refuses the grant outright, so there is
        // nothing to return rather than a division by zero.
        let g = SlotGrant {
            from: 100,
            to: 200,
            granularity_secs: 0,
        };
        assert_eq!(g.slot_at(150), None);

        // Inverted window: no `now` can satisfy both bounds.
        let inverted = SlotGrant {
            from: 200,
            to: 100,
            granularity_secs: 10,
        };
        assert_eq!(inverted.slot_at(150), None);
    }

    #[test]
    fn extreme_values_do_not_overflow_or_wrap() {
        // `from` at the top of the range: the lattice cannot step past `to`, and the
        // subtraction cannot wrap because `now >= from` is checked first.
        let g = SlotGrant {
            from: u64::MAX - 10,
            to: u64::MAX,
            granularity_secs: 4,
        };
        assert_eq!(g.slot_at(u64::MAX - 10), Some(u64::MAX - 10));
        assert_eq!(g.slot_at(u64::MAX), Some(u64::MAX - 2));
        assert_eq!(g.slot_at(u64::MAX - 11), None);

        // A granularity wider than the window: only the anchor slot exists.
        let wide = SlotGrant {
            from: 500,
            to: 600,
            granularity_secs: u64::MAX,
        };
        assert_eq!(wide.slot_at(550), Some(500));
    }
}
