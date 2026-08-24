pub mod detector;
pub mod escalation;
pub mod quorum;
pub mod resolver;

pub use detector::{
    conflicts_between, detect_conflicts, detect_nway_conflicts, Conflict, NWayConflict, QueuedSlot,
};
pub use escalation::{build_escalation, DisputeEscalation, EscalationInput};
pub use quorum::{resolve_by_quorum, QuorumResult};
pub use resolver::{
    resolve_conflict, resolve_nway_conflict, CandidateEvidence, ConflictEvidence, RelayObservation,
};
