//! Uptime-anchored clock (Phase 0 §4.2, D-clock).
//!
//! Phase 0 measured two things. Crystal drift is ~11 ppm (<1 s/day) — negligible
//! against a 60-second slot. Gross error is the real threat: a device was observed
//! sitting a full year behind true time while online, because auto-time was off and
//! the network alone does not correct the wall clock. So the protocol never trusts
//! the wall clock for slot validation.
//!
//! Instead the platform stores, at the last successful issuer contact, a pair
//! `(last_trusted_utc, uptime_at_anchor)` and computes "now" as:
//!
//! ```text
//! now = last_trusted_utc + (uptime_now - uptime_at_anchor)
//! ```
//!
//! This is immune to user tampering and NTP jumps and degrades to pure crystal
//! drift — seconds, not hours. It resets on reboot (uptime goes to zero), which is
//! exactly when the platform must re-anchor before trusting slots again.
//!
//! `Clock` is a trait so the core is testable and never touches a real system
//! clock directly (`07` Phase 1 requirement).

/// Skew tolerance in seconds (Phase 0 §4.2). Sized by gross error, not drift.
pub const SKEW_TOLERANCE_SECS: u64 = 5;

/// A clock the core can query for the current UTC second. Implementations must be
/// monotonic-derived (uptime-anchored), not raw wall clock — see module docs.
pub trait Clock {
    /// Current time as a UTC unix timestamp in seconds, or `None` if the anchor is
    /// invalid (e.g. just rebooted and not yet re-anchored), in which case slot
    /// validation must fail closed.
    fn now_utc(&self) -> Option<u64>;
}

/// The production clock: an anchor captured at last issuer contact plus the
/// device's monotonic uptime delta. `uptime_now` is supplied by the platform from
/// `/proc/uptime` (Android) or the equivalent monotonic source.
#[derive(Debug, Clone, Copy)]
pub struct UptimeAnchoredClock {
    pub last_trusted_utc: u64,
    pub uptime_at_anchor: u64,
    pub uptime_now: u64,
}

impl Clock for UptimeAnchoredClock {
    fn now_utc(&self) -> Option<u64> {
        // A monotonic clock cannot run backwards; if it appears to, the anchor is
        // stale (reboot) and we must not guess. Fail closed.
        let delta = self.uptime_now.checked_sub(self.uptime_at_anchor)?;
        self.last_trusted_utc.checked_add(delta)
    }
}

/// A fixed clock, for tests and for callers that have already computed "now".
#[derive(Debug, Clone, Copy)]
pub struct FixedClock(pub u64);

impl Clock for FixedClock {
    fn now_utc(&self) -> Option<u64> {
        Some(self.0)
    }
}
