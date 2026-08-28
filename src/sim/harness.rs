//! Seeded simulation harness that drives adversarial agents against real
//! conflict-detection / resolution APIs.

use crate::clock::{Clock, MockClock};
use crate::sim::agents::{AdversarialAgent, AgentCtx, AgentOutcome};
use crate::sim::trace::Trace;
use crate::sim::world::SimWorld;
use rand::rngs::StdRng;
use rand::SeedableRng;

/// Tunables for one harness run.
#[derive(Debug, Clone)]
pub struct SimConfig {
    pub seed: u64,
    /// Simulated start time (unix seconds).
    pub start_secs: u64,
    pub account: String,
    pub sequence: i64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            seed: 1,
            start_secs: 1_700_000_000,
            account: "GSIMACCOUNT0000000000000000000000000000".into(),
            sequence: 42,
        }
    }
}

impl SimConfig {
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }
}

/// Outcome of [`SimHarness::run`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimReport {
    pub seed: u64,
    pub trace: Trace,
    pub agent_summaries: Vec<(String, String)>,
}

impl SimReport {
    pub fn ok(&self) -> bool {
        self.trace.ok()
    }
}

/// Deterministic harness: one seeded RNG, one virtual clock, one world.
pub struct SimHarness {
    config: SimConfig,
    rng: StdRng,
    clock: MockClock,
    world: SimWorld,
    trace: Trace,
}

impl SimHarness {
    pub fn new(config: SimConfig) -> Self {
        let rng = StdRng::seed_from_u64(config.seed);
        let clock = MockClock::new(config.start_secs);
        let world = SimWorld::new(config.account.clone(), config.sequence);
        Self {
            config,
            rng,
            clock,
            world,
            trace: Trace::default(),
        }
    }

    pub fn seed(&self) -> u64 {
        self.config.seed
    }

    pub fn trace(&self) -> &Trace {
        &self.trace
    }

    /// Run `agents` in the given order. Each agent gets a fresh turn at the
    /// current simulated time; the harness advances the clock by 1s between
    /// agents so their trace timestamps are distinct but still determined
    /// solely by the seed + agent count.
    pub fn run(&mut self, agents: &[&dyn AdversarialAgent]) -> SimReport {
        self.trace.record(
            self.clock.now_secs(),
            "harness",
            "run_start",
            format!("seed={} agents={}", self.config.seed, agents.len()),
        );

        let mut summaries = Vec::new();

        for agent in agents {
            let mut ctx = AgentCtx {
                seed: self.config.seed,
                rng: &mut self.rng,
                clock: &self.clock,
                world: &mut self.world,
                trace: &mut self.trace,
            };
            let outcome = agent.act(&mut ctx);
            match outcome {
                AgentOutcome::Defended { summary } => {
                    summaries.push((agent.name().to_string(), summary));
                }
                AgentOutcome::InvariantViolation { summary } => {
                    summaries.push((agent.name().to_string(), summary.clone()));
                    // Trace already failed inside the agent in normal cases;
                    // ensure failure is set even if an agent forgot.
                    if self.trace.ok() {
                        self.trace.fail(summary);
                    }
                    break;
                }
            }
            self.clock.advance(1);
        }

        self.trace.record(
            self.clock.now_secs(),
            "harness",
            "run_end",
            format!("ok={}", self.trace.ok()),
        );

        SimReport {
            seed: self.config.seed,
            trace: self.trace.clone(),
            agent_summaries: summaries,
        }
    }
}
