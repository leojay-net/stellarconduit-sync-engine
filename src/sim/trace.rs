//! Append-only, order-stable execution trace for a single seeded run.

use serde::Serialize;

/// One recorded step. Kept deliberately small and `Serialize` so two runs
/// of the same seed can be compared by hashing the JSON (or by `PartialEq`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceEvent {
    /// Simulated time when the event was recorded (`MockClock` seconds).
    pub at_secs: u64,
    /// Agent or harness subsystem that produced the event.
    pub source: String,
    /// Stable verb, e.g. `"forged_proof_rejected"`, `"race_conflicts_detected"`.
    pub kind: String,
    /// Free-form but deterministic detail (hex ids, counts, reasons).
    pub detail: String,
}

/// Ordered log of [`TraceEvent`]s plus a terminal status line.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Trace {
    pub events: Vec<TraceEvent>,
    /// Empty on success; otherwise a stable invariant-violation message.
    pub failure: Option<String>,
}

impl Trace {
    pub fn record(
        &mut self,
        at_secs: u64,
        source: impl Into<String>,
        kind: impl Into<String>,
        detail: impl Into<String>,
    ) {
        self.events.push(TraceEvent {
            at_secs,
            source: source.into(),
            kind: kind.into(),
            detail: detail.into(),
        });
    }

    pub fn fail(&mut self, message: impl Into<String>) {
        self.failure = Some(message.into());
    }

    pub fn ok(&self) -> bool {
        self.failure.is_none()
    }

    /// Canonical fingerprint used by determinism tests and the sweep.
    pub fn fingerprint(&self) -> String {
        // serde_json preserves Vec order; field order follows derive order.
        serde_json::to_string(self).expect("Trace serialization is infallible")
    }
}
