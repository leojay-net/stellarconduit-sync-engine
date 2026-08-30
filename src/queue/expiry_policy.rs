//! Configurable, validated expiry policy for queued envelopes (issue #61).
//!
//! There is currently no single, explicit place that owns "how long can a
//! queued envelope wait before it is considered too stale to dispatch". This
//! module provides that place: an [`ExpiryPolicy`] mapping every
//! [`TxPriority`] to its own expiry window, with defaults that are documented
//! per tier and construction-time validation so a nonsensical policy fails
//! loudly instead of misbehaving silently at 2am.
//!
//! Design decisions:
//!
//! * **Struct fields, not `HashMap<TxPriority, Duration>`.** The tier set is
//!   fixed and known at compile time. Exhaustive struct fields mean the
//!   compiler enforces that every tier has a window (no missing-key bugs), no
//!   hashing overhead, and no silent fallthrough for unlisted priorities.
//! * **Plain unix-second timestamps.** The sync engine today stamps enqueue
//!   time with `unix_now()` (u64 seconds). #060's clock abstraction hasn't
//!   landed; when it does, it can wrap this API without changing its shape —
//!   the caller converts their clock reading to unix seconds and passes it in,
//!   keeping [`ExpiryPolicy::is_expired`] pure and trivially testable.
//! * **Fail at construction, not first use.** A policy where a lower-urgency
//!   tier expires sooner than a higher-urgency one (or where any window is
//!   zero) is almost certainly a configuration mistake. Rejecting it up front
//!   with a clear error beats discovering the mistake from user reports.
//!
//! Defaults and per-tier reasoning:
//!
//! | Tier      | Default    | Reasoning |
//! |-----------|------------|-----------|
//! | Emergency | 5 minutes  | An emergency payment that sits queued for longer than a few minutes has failed its purpose; after this window the staleness sweep should surface it to the user rather than send it silently. |
//! | Normal    | 1 hour     | Covers typical between-session gaps on a personal device; anything older than an hour probably belongs behind a "still want to send?" prompt. |
//! | Low       | 24 hours   | Low-priority traffic (batch syncs, non-urgent updates) is expected to wait out connectivity droughts; a full day gives opportunistic relays a fair chance. |
//!
//! Downstream adoption: issue #009 (staleness sweep) and #018 (settlement
//! timeout sweep) should consume this policy instead of inventing their own
//! ad hoc duration constants.

use crate::errors::SyncEngineError;
use crate::queue::priority::TxPriority;

/// Upper sanity bound: no queued envelope should be configured to live longer
/// than a week. Anything beyond that is a deployment misconfiguration, not a
/// retention policy.
pub const MAX_EXPIRY_SECS: u64 = 7 * 24 * 60 * 60;

/// Per-priority expiry windows for queued envelopes.
///
/// Construct via [`ExpiryPolicy::new`] (validated) or [`ExpiryPolicy::default`]
/// (documented defaults). See the module docs for per-tier reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExpiryPolicy {
    low_secs: u64,
    normal_secs: u64,
    emergency_secs: u64,
}

impl ExpiryPolicy {
    /// Validates and constructs a custom policy.
    ///
    /// Invariants enforced (all rejected with
    /// [`SyncEngineError::InvalidExpiryPolicy`]):
    ///
    /// 1. **Non-zero windows.** A zero-second window means "never dispatch",
    ///    which is a configuration bug rather than a policy.
    /// 2. **Monotonic urgency ordering.** Higher urgency must not expire
    ///    sooner-or-equal than lower urgency: `emergency <= normal <= low`
    ///    would make the most important envelopes die first.
    /// 3. **Sanity ceiling.** No window may exceed [`MAX_EXPIRY_SECS`] (one
    ///    week); longer values indicate a unit mistake (ms vs s) or a
    ///    misconfiguration.
    pub fn new(
        low_secs: u64,
        normal_secs: u64,
        emergency_secs: u64,
    ) -> Result<Self, SyncEngineError> {
        if low_secs == 0 || normal_secs == 0 || emergency_secs == 0 {
            return Err(SyncEngineError::InvalidExpiryPolicy(
                "expiry windows must be non-zero; a zero window means the tier can never be \
                 dispatched"
                    .to_string(),
            ));
        }

        if emergency_secs > normal_secs {
            return Err(SyncEngineError::InvalidExpiryPolicy(format!(
                "emergency expiry ({emergency_secs}s) exceeds normal expiry ({normal_secs}s); \
                 higher-urgency tiers must not outlive lower-urgency ones"
            )));
        }
        if normal_secs > low_secs {
            return Err(SyncEngineError::InvalidExpiryPolicy(format!(
                "normal expiry ({normal_secs}s) exceeds low expiry ({low_secs}s); \
                 higher-urgency tiers must not outlive lower-urgency ones"
            )));
        }

        if low_secs > MAX_EXPIRY_SECS {
            return Err(SyncEngineError::InvalidExpiryPolicy(format!(
                "low expiry {low_secs}s exceeds the sanity ceiling of {MAX_EXPIRY_SECS}s \
                 (one week); check for a ms-vs-s units mistake"
            )));
        }

        Ok(Self {
            low_secs,
            normal_secs,
            emergency_secs,
        })
    }

    /// The documented default policy. See the module docs for per-tier
    /// reasoning: Emergency 5 minutes, Normal 1 hour, Low 24 hours.
    pub fn default_policy() -> Self {
        Self {
            low_secs: 24 * 60 * 60,
            normal_secs: 60 * 60,
            emergency_secs: 5 * 60,
        }
    }

    /// Expiry window (in seconds) for the given priority tier.
    pub fn expiry_for(&self, priority: TxPriority) -> u64 {
        match priority {
            TxPriority::Low => self.low_secs,
            TxPriority::Normal => self.normal_secs,
            TxPriority::Emergency => self.emergency_secs,
        }
    }

    /// Whether an envelope of `priority`, enqueued at unix second
    /// `enqueued_at`, is expired as of unix second `now`.
    ///
    /// An envelope whose age exactly equals its tier's window counts as
    /// expired ("at or past" semantics) so sweeps do not need a +1 fudge.
    /// `now < enqueued_at` (clock skew) yields `false`: never expire an
    /// envelope because the clock appears to have run backwards.
    pub fn is_expired(&self, priority: TxPriority, enqueued_at: u64, now: u64) -> bool {
        if now < enqueued_at {
            return false;
        }
        now - enqueued_at >= self.expiry_for(priority)
    }
}

impl Default for ExpiryPolicy {
    fn default() -> Self {
        Self::default_policy()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_has_sensible_per_tier_ordering() {
        let policy = ExpiryPolicy::default();

        // Higher urgency must expire no later than lower urgency.
        assert!(policy.expiry_for(TxPriority::Emergency) <= policy.expiry_for(TxPriority::Normal));
        assert!(policy.expiry_for(TxPriority::Normal) <= policy.expiry_for(TxPriority::Low));

        // And every tier must have a non-zero window with documented reasoning
        // (spot-check the documented defaults).
        assert_eq!(policy.expiry_for(TxPriority::Emergency), 5 * 60);
        assert_eq!(policy.expiry_for(TxPriority::Normal), 60 * 60);
        assert_eq!(policy.expiry_for(TxPriority::Low), 24 * 60 * 60);

        // Defaults must satisfy their own validation invariants.
        assert!(ExpiryPolicy::new(
            policy.expiry_for(TxPriority::Low),
            policy.expiry_for(TxPriority::Normal),
            policy.expiry_for(TxPriority::Emergency),
        )
        .is_ok());
    }

    #[test]
    fn test_invalid_policy_construction_is_rejected() {
        // Inverted urgency ordering: emergency outliving normal is nonsense.
        let err = ExpiryPolicy::new(24 * 60 * 60, 60 * 60, 2 * 60 * 60)
            .expect_err("emergency > normal must be rejected");
        assert!(
            err.to_string().contains("must not outlive"),
            "unexpected error message: {err}"
        );

        // Inverted ordering between normal and low.
        assert!(ExpiryPolicy::new(60 * 60, 2 * 60 * 60, 5 * 60).is_err());

        // Zero window means "never dispatch" — a configuration bug.
        let err = ExpiryPolicy::new(0, 60, 30).expect_err("zero low window must be rejected");
        assert!(err.to_string().contains("non-zero"), "unexpected: {err}");

        // Above the sanity ceiling: likely a ms-vs-s units mistake.
        let err = ExpiryPolicy::new(365 * 24 * 60 * 60, 60 * 60, 5 * 60)
            .expect_err("multi-month low window must be rejected");
        assert!(
            err.to_string().contains("sanity ceiling"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_is_expired_respects_per_tier_window() {
        let policy = ExpiryPolicy::default();
        let enqueued_at = 1_700_000_000u64;

        // Emergency expires after 300s...
        assert!(!policy.is_expired(TxPriority::Emergency, enqueued_at, enqueued_at + 299));
        // ...exactly at the boundary it counts as expired ("at or past").
        assert!(policy.is_expired(TxPriority::Emergency, enqueued_at, enqueued_at + 300));

        // Normal is still alive at 300s where emergency already expired.
        assert!(!policy.is_expired(TxPriority::Normal, enqueued_at, enqueued_at + 300));
        assert!(policy.is_expired(TxPriority::Normal, enqueued_at, enqueued_at + 3_600));

        // Low lives a full day.
        assert!(!policy.is_expired(TxPriority::Low, enqueued_at, enqueued_at + 86_399));
        assert!(policy.is_expired(TxPriority::Low, enqueued_at, enqueued_at + 86_400));

        // Clock skew (now before enqueued_at) never expires an envelope.
        assert!(!policy.is_expired(TxPriority::Emergency, enqueued_at, enqueued_at - 10));
    }

    #[test]
    fn test_custom_policy_can_be_configured_at_construction() {
        // A shared relay terminal that wants tighter windows than the defaults.
        let policy = ExpiryPolicy::new(6 * 60 * 60, 10 * 60, 60).expect("valid custom policy");

        assert_eq!(policy.expiry_for(TxPriority::Low), 6 * 60 * 60);
        assert_eq!(policy.expiry_for(TxPriority::Normal), 10 * 60);
        assert_eq!(policy.expiry_for(TxPriority::Emergency), 60);

        let now = 1_000_000u64;
        assert!(!policy.is_expired(TxPriority::Emergency, now - 59, now));
        assert!(policy.is_expired(TxPriority::Emergency, now - 60, now));

        // Equal windows across tiers are legal (ordering invariant is <=).
        assert!(ExpiryPolicy::new(600, 600, 600).is_ok());

        // Default trait impl matches default_policy().
        assert_eq!(ExpiryPolicy::default(), ExpiryPolicy::default_policy());
    }
}
