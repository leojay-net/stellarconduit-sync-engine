//! Pluggable Byzantine adversarial agents for the simulation harness.

mod forged_proof;
mod race;
mod replay;

pub use forged_proof::ForgedProofAgent;
pub use race::RaceAgent;
pub use replay::ReplayAgent;

use crate::clock::MockClock;
use crate::sim::trace::Trace;
use crate::sim::world::SimWorld;
use rand::rngs::StdRng;

/// Mutable view an agent gets for one turn.
pub struct AgentCtx<'a> {
    pub seed: u64,
    pub rng: &'a mut StdRng,
    pub clock: &'a MockClock,
    pub world: &'a mut SimWorld,
    pub trace: &'a mut Trace,
}

/// Result of one agent turn. `InvariantViolation` fails the harness run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentOutcome {
    /// Attack was mounted and the system defended correctly.
    Defended { summary: String },
    /// Attack exposed a real bug / invariant break.
    InvariantViolation { summary: String },
}

/// Seed-driven adversarial behaviour. Implementations must be deterministic
/// given `ctx.rng` / `ctx.seed` — no wall clock, no `OsRng`, no dependence
/// on `HashMap` iteration order when recording outcomes.
pub trait AdversarialAgent: Send + Sync {
    fn name(&self) -> &'static str;
    fn act(&self, ctx: &mut AgentCtx<'_>) -> AgentOutcome;
}
