//! Monotonic Clock Abstraction for TTL and Staleness Calculations.
//!
//! This module provides a robust clock abstraction to prevent time-jump anomalies
//! during staleness and TTL calculations. It resolves the tension between needing
//! a purely monotonic clock (which resets on process restart) and needing persisted
//! timestamps (which rely on the wall clock).

use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

/// A clock abstraction for deterministic testing and handling clock regression.
pub trait Clock: Send + Sync + std::fmt::Debug {
    /// Returns the current time in Unix seconds.
    fn now_secs(&self) -> u64;

    /// Safely calculates the elapsed seconds since `earlier_secs`.
    ///
    /// If a clock regression across restarts caused `earlier_secs` to be in the future,
    /// this clamps the elapsed time to 0 and logs a warning to prevent negative durations.
    fn elapsed_since(&self, earlier_secs: u64) -> u64 {
        let now = self.now_secs();
        if now >= earlier_secs {
            now - earlier_secs
        } else {
            log::warn!(
                "Clock regression detected: timestamp {} is in the future relative to now {}. Clamping elapsed time to 0.",
                earlier_secs, now
            );
            0
        }
    }
}

/// A clock that is monotonically increasing intra-session, anchored to the wall-clock at creation.
///
/// This resolves the persisted-monotonic tension:
/// - Upon instantiation, it snapshots `SystemTime::now()` (`baseline_wall`) and `Instant::now()` (`baseline_monotonic`).
/// - `now_secs()` returns `baseline_wall` + elapsed time since `baseline_monotonic`.
///
/// This guarantees strict monotonic behavior *within* a single process session (immune to NTP/user changes while running),
/// while still being anchored to a Unix timestamp that makes sense when persisted across process restarts.
#[derive(Debug)]
pub struct HybridClock {
    baseline_wall_secs: u64,
    baseline_monotonic: Instant,
}

impl HybridClock {
    pub fn new() -> Self {
        let baseline_wall_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            baseline_wall_secs,
            baseline_monotonic: Instant::now(),
        }
    }
}

impl Default for HybridClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for HybridClock {
    fn now_secs(&self) -> u64 {
        self.baseline_wall_secs + self.baseline_monotonic.elapsed().as_secs()
    }
}

/// A mock clock for deterministic testing.
#[derive(Debug, Default)]
pub struct MockClock {
    current_time: Arc<Mutex<u64>>,
}

impl MockClock {
    pub fn new(initial_secs: u64) -> Self {
        Self {
            current_time: Arc::new(Mutex::new(initial_secs)),
        }
    }

    pub fn advance(&self, secs: u64) {
        let mut time = self.current_time.lock().unwrap();
        *time += secs;
    }

    pub fn set_time(&self, secs: u64) {
        let mut time = self.current_time.lock().unwrap();
        *time = secs;
    }
}

impl Clock for MockClock {
    fn now_secs(&self) -> u64 {
        *self.current_time.lock().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_elapsed_time_calculation() {
        let clock = MockClock::new(100);
        assert_eq!(clock.elapsed_since(80), 20);
        assert_eq!(clock.elapsed_since(100), 0);
    }

    #[test]
    fn test_clock_regression_does_not_produce_negative_elapsed() {
        let clock = MockClock::new(100);
        // Pretend a restart happened and the system wall clock jumped backwards,
        // so the previously persisted timestamp (150) is now in the future relative to our current clock.
        // It should clamp to 0.
        assert_eq!(clock.elapsed_since(150), 0);
    }

    #[test]
    fn test_clock_abstraction_is_injectable_and_deterministic_in_tests() {
        let clock = MockClock::new(100);
        assert_eq!(clock.now_secs(), 100);

        clock.advance(50);
        assert_eq!(clock.now_secs(), 150);
        assert_eq!(clock.elapsed_since(100), 50);

        clock.set_time(50);
        assert_eq!(clock.now_secs(), 50);
        // Clamps to 0 because 100 is in the future relative to 50
        assert_eq!(clock.elapsed_since(100), 0);
    }

    #[test]
    fn test_hybrid_clock_is_monotonic_intra_session() {
        let clock = HybridClock::new();
        let first = clock.now_secs();
        // Since it relies on Instant, it can never go backwards, even if we sleep or don't sleep.
        let second = clock.now_secs();
        assert!(second >= first);
    }
}
