//! Deterministic simulation harness and Byzantine adversarial agents.
//!
//! # Why this module exists
//!
//! Issue `#049` calls for a seeded discrete-event harness that drives the
//! sync engine's *real* conflict / settlement logic under injectable faults.
//! Issue `#070` extends that harness with actively adversarial participants
//! (forged proofs, stale replay, deliberate races) — a different threat
//! model from honest crashes and delays.
//!
//! `#049` has not landed as a standalone crate yet. This module provides the
//! **stable harness API** `#070` needs to attach to: a seeded RNG, a virtual
//! clock ([`crate::clock::MockClock`]), an append-only execution
//! [`trace::Trace`], pluggable [`agents::AdversarialAgent`] behaviours, and a
//! budgeted [`sweep`] runner suitable for CI. Honest fault injection from
//! `#049` can grow behind the same types without breaking agent code.
//!
//! # Determinism contract
//!
//! Given the same `seed` and the same ordered agent list, [`harness::SimHarness::run`]
//! always produces an identical [`trace::Trace`] (same events, same
//! invariant outcomes). Agents must not touch wall clocks, OS entropy, or
//! unordered hash iteration when recording results.
//!
//! # Adversarial agents (`#070`)
//!
//! | Agent | Attack | What it stresses |
//! |-------|--------|------------------|
//! | [`agents::ForgedProofAgent`] | Tampered / cross-wired relay proofs | Resolver signature checks; precursor to `#046` chain-integrity |
//! | [`agents::ReplayAgent`] | Re-inject previously-valid observations out of context | Sequence binding + staleness |
//! | [`agents::RaceAgent`] | Two conflicting envelopes at the same simulated tick, permuted arrival order | Conflict detection completeness + **output-order stability** |
//!
//! # Running a sweep
//!
//! ```text
//! # Bounded CI sweep (also wired in .github/workflows/ci.yml)
//! cargo test --test adversarial_sweep -- --nocapture
//!
//! # Larger manual / nightly sweep
//! ADVERSARIAL_SWEEP_SEEDS=5000 cargo test --test adversarial_sweep -- --nocapture
//! ```

pub mod agents;
pub mod harness;
pub mod sweep;
pub mod trace;
pub mod world;

pub use agents::{
    AdversarialAgent, AgentCtx, AgentOutcome, ForgedProofAgent, RaceAgent, ReplayAgent,
};
pub use harness::{SimConfig, SimHarness, SimReport};
pub use sweep::{run_adversarial_sweep, SweepConfig, SweepReport};
pub use trace::{Trace, TraceEvent};
pub use world::{SimDevice, SimWorld};
