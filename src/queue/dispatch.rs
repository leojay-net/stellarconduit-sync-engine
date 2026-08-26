//! In-flight dispatch backpressure per relay session (issue #58).
//!
//! Nothing in [`OutboundTxQueue`](crate::queue::priority::OutboundTxQueue)
//! limits how many popped envelopes can be handed to a relay concurrently —
//! a caller could drain the whole queue onto one BLE/WiFi-Direct link and
//! overwhelm it. This module provides the missing bound: a
//! [`DispatchWindow`] that tracks popped-but-not-yet-acknowledged envelopes
//! per relay session and refuses further dispatch once full.
//!
//! # The acknowledgment contract
//!
//! This crate owns queueing only — it never sees transport events (BLE
//! writes, WiFi-Direct frames, relay TCP state). The contract is therefore
//! deliberately narrow and driven entirely by explicit calls from the
//! embedding application:
//!
//! 1. **`try_acquire(message_id, now)`** — MUST be called before handing a
//!    popped envelope to the relay. Returns
//!    [`SyncEngineError::BackpressureWindowFull`] if the window is at
//!    capacity; the caller should stop dispatching and retry later (acks
//!    landing or timeouts expiring free slots).
//! 2. **`acknowledge(message_id)`** — the embedder MUST call this when the
//!    relay confirms propagation of the envelope. What "confirmed" means is
//!    defined one layer up (e.g. a settlement status transition out of
//!    `Propagating`, or an application-level relay ack frame) — this crate
//!    deliberately does not own or observe that transition.
//! 3. **`abandon(message_id)`** — optional immediate release for callers
//!    that know an envelope will never be acknowledged (e.g. the transport
//!    reported a hard failure for that specific message).
//!
//! Anything else (relay connection state, link quality, retransmission) is
//! out of scope for this crate.
//!
//! # Dead relay sessions
//!
//! If a relay session ends uncleanly its window entries are never
//! acknowledged. Every mutating call sweeps entries older than the
//! configured timeout, so a dead session's slots are released automatically
//! without anyone special-casing it. A timeout should comfortably exceed the
//! relay's normal ack latency; see [`DispatchWindow::new`]'s validation.

use crate::errors::SyncEngineError;
use std::collections::HashMap;

/// Default in-flight capacity. BLE links in this project's target topology
/// tolerate only a handful of concurrent operations; eight leaves headroom
/// for interleaved acks without allowing a flood.
pub const DEFAULT_MAX_IN_FLIGHT: usize = 8;

/// Default release timeout (seconds). Should comfortably exceed the worst
/// normal relay ack latency so healthy slow links aren't double-dispatched.
pub const DEFAULT_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DispatchEntry {
    dispatched_at: u64,
}

/// Bounds how many popped-but-unacknowledged envelopes may be outstanding.
///
/// Construct via [`DispatchWindow::new`] (validated) or
/// [`DispatchWindow::default`]. All lookup paths sweep expired entries first,
/// so a dead relay session's capacity is reclaimed automatically.
#[derive(Debug)]
pub struct DispatchWindow {
    max_in_flight: usize,
    timeout_secs: u64,
    in_flight: HashMap<[u8; 32], DispatchEntry>,
}

impl DispatchWindow {
    /// Validates and constructs a dispatch window.
    ///
    /// Invariants enforced ([`SyncEngineError::InvalidDispatchWindow`]):
    ///
    /// 1. **Non-zero capacity.** A zero window can never dispatch anything;
    ///    that is a configuration bug, not a policy.
    /// 2. **Non-zero timeout.** With a zero timeout every entry would expire
    ///    instantly, silently disabling backpressure altogether.
    pub fn new(max_in_flight: usize, timeout_secs: u64) -> Result<Self, SyncEngineError> {
        if max_in_flight == 0 {
            return Err(SyncEngineError::InvalidDispatchWindow(
                "max_in_flight must be non-zero; a zero window can never dispatch".to_string(),
            ));
        }
        if timeout_secs == 0 {
            return Err(SyncEngineError::InvalidDispatchWindow(
                "timeout_secs must be non-zero; a zero timeout disables backpressure by \
                 expiring every entry immediately"
                    .to_string(),
            ));
        }
        Ok(Self {
            max_in_flight,
            timeout_secs,
            in_flight: HashMap::new(),
        })
    }

    /// Sweeps entries whose ack never arrived within the timeout. Called on
    /// every mutating/inspecting path so dead-relay slots are reclaimed
    /// without any dedicated timer.
    fn sweep_expired(&mut self, now: u64) {
        self.in_flight
            .retain(|_, entry| now.saturating_sub(entry.dispatched_at) < self.timeout_secs);
    }

    /// Reserves a window slot for `message_id`.
    ///
    /// Errors with [`SyncEngineError::BackpressureWindowFull`] when the window
    /// is at capacity (after sweeping expired entries), or
    /// [`SyncEngineError::DuplicateInFlight`] when the same message is already
    /// outstanding — a duplicate would double-count against the window and
    /// indicates a caller bug.
    pub fn try_acquire(&mut self, message_id: [u8; 32], now: u64) -> Result<(), SyncEngineError> {
        self.sweep_expired(now);

        if self.in_flight.contains_key(&message_id) {
            return Err(SyncEngineError::DuplicateInFlight);
        }
        if self.in_flight.len() >= self.max_in_flight {
            return Err(SyncEngineError::BackpressureWindowFull {
                max_in_flight: self.max_in_flight,
            });
        }
        self.in_flight
            .insert(message_id, DispatchEntry { dispatched_at: now });
        Ok(())
    }

    /// Releases the slot for a relay-acknowledged envelope.
    ///
    /// Returns `true` if the envelope was in flight (slot freed), `false` if
    /// it had already been released (e.g. swept by timeout) — a late ack after
    /// a timeout release is benign but worth knowing about.
    pub fn acknowledge(&mut self, message_id: &[u8; 32]) -> bool {
        self.in_flight.remove(message_id).is_some()
    }

    /// Immediately releases a slot without an ack — for transports that
    /// report a hard, final failure for a specific message.
    pub fn abandon(&mut self, message_id: &[u8; 32]) -> bool {
        self.acknowledge(message_id)
    }

    /// Releases every entry older than the timeout as of `now`. Useful for a
    /// periodic sweep from the embedder's tick loop; ordinary calls already
    /// sweep lazily.
    pub fn release_expired(&mut self, now: u64) -> usize {
        let before = self.in_flight.len();
        self.sweep_expired(now);
        before - self.in_flight.len()
    }

    /// Number of currently-outstanding envelopes (after expiry sweep).
    pub fn in_flight_count(&mut self, now: u64) -> usize {
        self.sweep_expired(now);
        self.in_flight.len()
    }

    /// Whether the window is at capacity (after expiry sweep).
    pub fn is_at_capacity(&mut self, now: u64) -> bool {
        self.in_flight_count(now) >= self.max_in_flight
    }

    /// Configured capacity.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }

    /// Configured release timeout (seconds).
    pub fn timeout_secs(&self) -> u64 {
        self.timeout_secs
    }
}

impl Default for DispatchWindow {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_IN_FLIGHT, DEFAULT_TIMEOUT_SECS)
            .expect("default dispatch window parameters are valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_id(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    #[test]
    fn test_dispatch_blocked_when_window_full() {
        let mut window = DispatchWindow::new(2, 120).expect("valid config");
        let now = 1_000_000u64;

        window.try_acquire(msg_id(1), now).expect("first slot");
        window.try_acquire(msg_id(2), now).expect("second slot");

        // Window is full — the next dispatch must be refused with a clear,
        // retryable signal, never silently allowed and never blocking.
        let err = window
            .try_acquire(msg_id(3), now)
            .expect_err("window is full");
        match err {
            SyncEngineError::BackpressureWindowFull { max_in_flight } => {
                assert_eq!(max_in_flight, 2);
            }
            other => panic!("expected BackpressureWindowFull, got: {other:?}"),
        }
    }

    #[test]
    fn test_window_slot_released_on_acknowledgment() {
        let mut window = DispatchWindow::new(1, 120).expect("valid config");
        let now = 1_000_000u64;

        window.try_acquire(msg_id(1), now).expect("acquire");
        assert!(window.is_at_capacity(now));

        // Relay confirms propagation → slot freed → next dispatch succeeds.
        assert!(window.acknowledge(&msg_id(1)));
        assert!(!window.is_at_capacity(now));
        window
            .try_acquire(msg_id(2), now + 10)
            .expect("slot after ack");

        // A late duplicate ack for an already-released entry is benign.
        assert!(!window.acknowledge(&msg_id(1)));
    }

    #[test]
    fn test_window_slot_released_on_timeout_for_dead_relay() {
        let mut window = DispatchWindow::new(1, 60).expect("valid config");

        // Dead relay: acquired at t=1000, never acknowledged.
        window.try_acquire(msg_id(1), 1_000).expect("acquire");

        // Well before the timeout the slot is still held...
        assert!(window.is_at_capacity(1_050));
        assert!(window.try_acquire(msg_id(2), 1_050).is_err());

        // ...past the timeout the sweep reclaims it for a new dispatch.
        window
            .try_acquire(msg_id(3), 1_061)
            .expect("timeout released dead slot");
        assert_eq!(window.in_flight_count(1_061), 1);

        // Explicit bulk sweep reports what it reclaimed too.
        let reclaimed = window.release_expired(1_200);
        assert_eq!(reclaimed, 1);
        assert_eq!(window.in_flight_count(1_200), 0);
    }

    #[test]
    fn test_window_size_is_configurable() {
        // Capacity comes from the caller, not a constant...
        let mut small = DispatchWindow::new(1, 120).expect("valid");
        let mut large = DispatchWindow::new(64, 120).expect("valid");
        assert_eq!(small.max_in_flight(), 1);
        assert_eq!(large.max_in_flight(), 64);
        let now = 500u64;

        small.try_acquire(msg_id(1), now).expect("fills small");
        assert!(small.try_acquire(msg_id(2), now).is_err());
        for seed in 1..=64u8 {
            large
                .try_acquire(msg_id(seed), now)
                .expect("large has room");
        }
        assert!(large.is_at_capacity(now));

        // ...and so does the release timeout.
        let fast = DispatchWindow::new(4, 5).expect("valid");
        assert_eq!(fast.timeout_secs(), 5);
    }

    #[test]
    fn duplicate_acquire_is_rejected() {
        let mut window = DispatchWindow::default();
        let now = 42u64;
        window.try_acquire(msg_id(9), now).expect("first acquire");
        assert!(matches!(
            window.try_acquire(msg_id(9), now),
            Err(SyncEngineError::DuplicateInFlight)
        ));
    }

    #[test]
    fn abandon_releases_immediately() {
        let mut window = DispatchWindow::new(1, 600).expect("valid"); // long timeout
        let now = 100u64;
        window.try_acquire(msg_id(4), now).expect("acquire");

        // Transport reported a hard failure — no ack will ever come.
        assert!(window.abandon(&msg_id(4)));
        window
            .try_acquire(msg_id(5), now + 1)
            .expect("slot freed by abandon");
    }

    #[test]
    fn invalid_constructor_config_is_rejected() {
        assert!(matches!(
            DispatchWindow::new(0, 120),
            Err(SyncEngineError::InvalidDispatchWindow(_))
        ));
        assert!(matches!(
            DispatchWindow::new(8, 0),
            Err(SyncEngineError::InvalidDispatchWindow(_))
        ));
    }
}
