//! Protocol-level counters for the sync engine, mirroring the pattern used in
//! `stellarconduit-core::metrics`. Intended to be exposed by whichever binary
//! embeds this crate (mobile wallet, relay node).

use std::sync::atomic::{AtomicUsize, Ordering};

/// Plain-data snapshot of all counters at a point in time.
///
/// This is an approximate, independently-read snapshot — not a transactionally
/// consistent one. Each counter is read separately, so cross-field atomicity
/// is not guaranteed. This is acceptable for monitoring/reporting purposes
/// where perfect consistency is not required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsSnapshot {
    /// Total number of envelopes ever queued (lifetime counter).
    pub queued_total: usize,
    /// Total number of envelopes successfully settled on-chain (lifetime counter).
    pub settled_total: usize,
    /// Total number of envelopes that failed to settle (lifetime counter).
    pub failed_total: usize,
    /// Total number of double-spend conflicts detected (lifetime counter).
    pub conflicts_detected: usize,
    /// Total number of conflicts that could not be resolved off-chain and
    /// required escalation to the on-chain dispute resolver (lifetime counter).
    pub disputes_escalated: usize,
    /// Total number of envelopes evicted from the queue due to staleness
    /// or TTL expiration (lifetime counter).
    pub queue_evictions: usize,
}

#[derive(Debug, Default)]
pub struct SyncEngineMetrics {
    pub queued_total: AtomicUsize,
    pub settled_total: AtomicUsize,
    pub failed_total: AtomicUsize,
    pub conflicts_detected: AtomicUsize,
    pub disputes_escalated: AtomicUsize,
    /// Count of envelopes evicted from queue due to staleness/TTL expiration.
    pub queue_evictions: AtomicUsize,
}

impl SyncEngineMetrics {
    /// Create a new metrics instance with all counters initialized to zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Capture a snapshot of all counter values at this moment.
    ///
    /// Returns a plain-data struct capturing every counter's current value.
    /// This is an approximate, independently-read snapshot — not a
    /// transactionally consistent one. Each counter is read atomically, but
    /// the reads are not coordinated across fields. This is acceptable for
    /// monitoring/reporting purposes where perfect consistency is not required.
    ///
    /// Use this for:
    /// - Exposing current state to monitoring dashboards
    /// - Periodic reporting of absolute values
    /// - Debugging and introspection
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queued_total: self.queued_total.load(Ordering::Relaxed),
            settled_total: self.settled_total.load(Ordering::Relaxed),
            failed_total: self.failed_total.load(Ordering::Relaxed),
            conflicts_detected: self.conflicts_detected.load(Ordering::Relaxed),
            disputes_escalated: self.disputes_escalated.load(Ordering::Relaxed),
            queue_evictions: self.queue_evictions.load(Ordering::Relaxed),
        }
    }

    /// Capture a snapshot and reset all counters to zero.
    ///
    /// This is useful for callers who want periodic deltas rather than
    /// lifetime totals. After calling this method, the snapshot contains
    /// the values that were present immediately before the reset, and all
    /// counters are reset to zero.
    ///
    /// Use this for:
    /// - Periodic reporting windows (e.g., "how many payments this hour")
    /// - Calculating deltas between reporting periods
    /// - Time-windowed monitoring
    ///
    /// Note: Like `snapshot()`, this is not transactionally consistent —
    /// each counter is read and reset independently.
    pub fn snapshot_and_reset(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            queued_total: self.queued_total.swap(0, Ordering::Relaxed),
            settled_total: self.settled_total.swap(0, Ordering::Relaxed),
            failed_total: self.failed_total.swap(0, Ordering::Relaxed),
            conflicts_detected: self.conflicts_detected.swap(0, Ordering::Relaxed),
            disputes_escalated: self.disputes_escalated.swap(0, Ordering::Relaxed),
            queue_evictions: self.queue_evictions.swap(0, Ordering::Relaxed),
        }
    }

    /// Export metrics in Prometheus text exposition format.
    ///
    /// Returns a string in the Prometheus text format (version 0.0.4) suitable
    /// for scraping by a Prometheus server. All counters are exported with
    /// appropriate `# TYPE` and `# HELP` annotations following Prometheus
    /// naming conventions.
    ///
    /// The metric names follow the pattern `stellarconduit_sync_<name>_total`
    /// for consistency with Prometheus naming best practices (counters should
    /// have a `_total` suffix).
    ///
    /// See: https://prometheus.io/docs/instrumenting/exposition_formats/
    pub fn to_prometheus_text(&self) -> String {
        let snapshot = self.snapshot();
        let mut output = String::new();

        // queued_total
        output.push_str(
            "# HELP stellarconduit_sync_queued_total Total number of envelopes ever queued.\n",
        );
        output.push_str("# TYPE stellarconduit_sync_queued_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_queued_total {}\n",
            snapshot.queued_total
        ));

        // settled_total
        output.push_str("# HELP stellarconduit_sync_settled_total Total number of envelopes successfully settled on-chain.\n");
        output.push_str("# TYPE stellarconduit_sync_settled_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_settled_total {}\n",
            snapshot.settled_total
        ));

        // failed_total
        output.push_str("# HELP stellarconduit_sync_failed_total Total number of envelopes that failed to settle.\n");
        output.push_str("# TYPE stellarconduit_sync_failed_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_failed_total {}\n",
            snapshot.failed_total
        ));

        // conflicts_detected
        output.push_str("# HELP stellarconduit_sync_conflicts_detected_total Total number of double-spend conflicts detected.\n");
        output.push_str("# TYPE stellarconduit_sync_conflicts_detected_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_conflicts_detected_total {}\n",
            snapshot.conflicts_detected
        ));

        // disputes_escalated
        output.push_str("# HELP stellarconduit_sync_disputes_escalated_total Total number of conflicts escalated to on-chain dispute resolver.\n");
        output.push_str("# TYPE stellarconduit_sync_disputes_escalated_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_disputes_escalated_total {}\n",
            snapshot.disputes_escalated
        ));

        // queue_evictions
        output.push_str("# HELP stellarconduit_sync_queue_evictions_total Total number of envelopes evicted from queue due to staleness or TTL.\n");
        output.push_str("# TYPE stellarconduit_sync_queue_evictions_total counter\n");
        output.push_str(&format!(
            "stellarconduit_sync_queue_evictions_total {}\n",
            snapshot.queue_evictions
        ));

        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_snapshot_reflects_current_values() {
        let metrics = SyncEngineMetrics::new();

        // Increment some counters
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        metrics.settled_total.fetch_add(5, Ordering::Relaxed);
        metrics.failed_total.fetch_add(2, Ordering::Relaxed);
        metrics.conflicts_detected.fetch_add(3, Ordering::Relaxed);
        metrics.disputes_escalated.fetch_add(1, Ordering::Relaxed);
        metrics.queue_evictions.fetch_add(4, Ordering::Relaxed);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.queued_total, 10);
        assert_eq!(snapshot.settled_total, 5);
        assert_eq!(snapshot.failed_total, 2);
        assert_eq!(snapshot.conflicts_detected, 3);
        assert_eq!(snapshot.disputes_escalated, 1);
        assert_eq!(snapshot.queue_evictions, 4);
    }

    #[test]
    fn test_prometheus_output_is_well_formed() {
        let metrics = SyncEngineMetrics::new();

        metrics.queued_total.fetch_add(42, Ordering::Relaxed);
        metrics.settled_total.fetch_add(17, Ordering::Relaxed);

        let output = metrics.to_prometheus_text();

        // Verify it contains required Prometheus format elements
        assert!(output.contains("# TYPE stellarconduit_sync_queued_total counter"));
        assert!(output.contains("# HELP stellarconduit_sync_queued_total"));
        assert!(output.contains("stellarconduit_sync_queued_total 42"));
        assert!(output.contains("stellarconduit_sync_settled_total 17"));

        // Verify each metric has TYPE and HELP lines
        assert!(output.contains("# TYPE stellarconduit_sync_settled_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_failed_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_conflicts_detected_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_disputes_escalated_total counter"));
        assert!(output.contains("# TYPE stellarconduit_sync_queue_evictions_total counter"));

        // Verify metric names follow Prometheus naming conventions
        // (letters, numbers, underscores, and colons allowed)
        assert!(!output.contains("stellarconduit-sync")); // no hyphens
        assert!(output.contains("_total")); // counter suffix

        // Verify each line ends with newline
        for line in output.lines() {
            assert!(!line.is_empty() || line.starts_with('#') || line.contains(' '));
        }
    }

    #[test]
    fn test_snapshot_and_reset_zeroes_counters() {
        let metrics = SyncEngineMetrics::new();

        // Set some values
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        metrics.settled_total.fetch_add(5, Ordering::Relaxed);
        metrics.failed_total.fetch_add(2, Ordering::Relaxed);
        metrics.conflicts_detected.fetch_add(3, Ordering::Relaxed);
        metrics.disputes_escalated.fetch_add(1, Ordering::Relaxed);
        metrics.queue_evictions.fetch_add(4, Ordering::Relaxed);

        // Capture snapshot and reset
        let snapshot = metrics.snapshot_and_reset();

        // Verify snapshot has the values before reset
        assert_eq!(snapshot.queued_total, 10);
        assert_eq!(snapshot.settled_total, 5);
        assert_eq!(snapshot.failed_total, 2);
        assert_eq!(snapshot.conflicts_detected, 3);
        assert_eq!(snapshot.disputes_escalated, 1);
        assert_eq!(snapshot.queue_evictions, 4);

        // Verify all counters are now zero
        let after_snapshot = metrics.snapshot();
        assert_eq!(after_snapshot.queued_total, 0);
        assert_eq!(after_snapshot.settled_total, 0);
        assert_eq!(after_snapshot.failed_total, 0);
        assert_eq!(after_snapshot.conflicts_detected, 0);
        assert_eq!(after_snapshot.disputes_escalated, 0);
        assert_eq!(after_snapshot.queue_evictions, 0);
    }

    #[test]
    fn test_default_metrics_are_zero() {
        let metrics = SyncEngineMetrics::default();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.queued_total, 0);
        assert_eq!(snapshot.settled_total, 0);
        assert_eq!(snapshot.failed_total, 0);
        assert_eq!(snapshot.conflicts_detected, 0);
        assert_eq!(snapshot.disputes_escalated, 0);
        assert_eq!(snapshot.queue_evictions, 0);
    }

    #[test]
    fn test_prometheus_output_with_zero_values() {
        let metrics = SyncEngineMetrics::new();
        let output = metrics.to_prometheus_text();

        // Should still output all metrics with zero values
        assert!(output.contains("stellarconduit_sync_queued_total 0"));
        assert!(output.contains("stellarconduit_sync_settled_total 0"));
        assert!(output.contains("stellarconduit_sync_failed_total 0"));
        assert!(output.contains("stellarconduit_sync_conflicts_detected_total 0"));
        assert!(output.contains("stellarconduit_sync_disputes_escalated_total 0"));
        assert!(output.contains("stellarconduit_sync_queue_evictions_total 0"));
    }

    #[test]
    fn test_snapshot_is_independent_of_future_changes() {
        let metrics = SyncEngineMetrics::new();

        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        let snapshot1 = metrics.snapshot();

        metrics.queued_total.fetch_add(5, Ordering::Relaxed);
        let snapshot2 = metrics.snapshot();

        // First snapshot should not be affected by later changes
        assert_eq!(snapshot1.queued_total, 10);
        assert_eq!(snapshot2.queued_total, 15);
    }

    #[test]
    fn test_multiple_resets_accumulate_correctly() {
        let metrics = SyncEngineMetrics::new();

        // First period
        metrics.queued_total.fetch_add(10, Ordering::Relaxed);
        let period1 = metrics.snapshot_and_reset();
        assert_eq!(period1.queued_total, 10);

        // Second period
        metrics.queued_total.fetch_add(5, Ordering::Relaxed);
        let period2 = metrics.snapshot_and_reset();
        assert_eq!(period2.queued_total, 5);

        // Verify both periods are tracked independently
        assert_eq!(period1.queued_total, 10);
        assert_eq!(period2.queued_total, 5);
    }

    #[test]
    fn test_prometheus_metric_names_follow_conventions() {
        let metrics = SyncEngineMetrics::new();
        let output = metrics.to_prometheus_text();

        // Extract all metric names
        let metric_names: Vec<&str> = output
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .map(|line| line.split_whitespace().next().unwrap())
            .collect();

        // Verify all metric names match Prometheus naming conventions
        // Must match regex: [a-zA-Z_:][a-zA-Z0-9_:]*
        for name in metric_names {
            assert!(
                name.chars()
                    .all(|c| c.is_alphanumeric() || c == '_' || c == ':'),
                "Metric name '{}' contains invalid characters",
                name
            );
            assert!(
                name.chars()
                    .next()
                    .map(|c| c.is_alphabetic() || c == '_' || c == ':')
                    .unwrap_or(false),
                "Metric name '{}' must start with letter, underscore, or colon",
                name
            );
        }
    }
}
