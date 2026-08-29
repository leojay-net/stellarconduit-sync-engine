pub mod detector;
pub mod escalation;
pub mod quorum;
pub mod reconciliation;
pub mod resolver;
pub mod vrf_tiebreak;

pub use detector::{
    conflicts_between, detect_conflicts, detect_nway_conflicts, Conflict, NWayConflict, QueuedSlot,
};
pub use escalation::{build_escalation, DisputeEscalation, EscalationInput};
pub use quorum::{resolve_by_quorum, QuorumResult};
pub use reconciliation::{
    classify as classify_divergence, reconverge, DivergenceClass, Reconvergence, ResolutionSummary,
};
pub use resolver::{
    quorum_standing, resolve_conflict, resolve_conflict_with_tiebreak, resolve_nway_conflict,
    CandidateEvidence, ConflictEvidence, QuorumStanding, RelayObservation,
};
pub use vrf_tiebreak::{
    select_tiebreak_evaluator, verify_tiebreak, verify_tiebreak_with_evaluator, vrf_tiebreak,
    RelayVrfIdentity, TiebreakOutcome,
};
