//! Budgeted multi-seed adversarial sweep.

use std::time::{Duration, Instant};

use crate::sim::agents::{AdversarialAgent, ForgedProofAgent, RaceAgent, ReplayAgent};
use crate::sim::harness::{SimConfig, SimHarness};

/// Sweep knobs. CI uses a small `max_seeds` + short `time_budget`; nightly /
/// manual runs raise `max_seeds` via `ADVERSARIAL_SWEEP_SEEDS`.
#[derive(Debug, Clone)]
pub struct SweepConfig {
    pub start_seed: u64,
    pub max_seeds: u64,
    pub time_budget: Duration,
}

impl Default for SweepConfig {
    fn default() -> Self {
        Self {
            start_seed: 1,
            max_seeds: 256,
            time_budget: Duration::from_secs(30),
        }
    }
}

impl SweepConfig {
    /// Resolve from env for CI / nightly: `ADVERSARIAL_SWEEP_SEEDS` and
    /// `ADVERSARIAL_SWEEP_BUDGET_SECS`.
    pub fn from_env_or_default() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("ADVERSARIAL_SWEEP_SEEDS") {
            if let Ok(n) = v.parse() {
                cfg.max_seeds = n;
            }
        }
        if let Ok(v) = std::env::var("ADVERSARIAL_SWEEP_BUDGET_SECS") {
            if let Ok(n) = v.parse::<u64>() {
                cfg.time_budget = Duration::from_secs(n);
            }
        }
        cfg
    }
}

#[derive(Debug, Clone)]
pub struct SweepReport {
    pub seeds_run: u64,
    pub failures: Vec<(u64, String)>,
    pub elapsed: Duration,
    pub hit_budget: bool,
}

impl SweepReport {
    pub fn ok(&self) -> bool {
        self.failures.is_empty()
    }
}

/// Run the three `#070` agents on every seed until `max_seeds` or the time
/// budget is exhausted. Prints seed + failure detail on the first break so
/// a CI log is itself a reproduction recipe.
pub fn run_adversarial_sweep(config: SweepConfig) -> SweepReport {
    let agents: [&dyn AdversarialAgent; 3] = [&ForgedProofAgent, &ReplayAgent, &RaceAgent];
    let started = Instant::now();
    let mut seeds_run = 0u64;
    let mut failures = Vec::new();
    let mut hit_budget = false;

    for offset in 0..config.max_seeds {
        if started.elapsed() >= config.time_budget {
            hit_budget = true;
            break;
        }
        let seed = config.start_seed.wrapping_add(offset);
        let mut harness = SimHarness::new(SimConfig::default().with_seed(seed));
        let report = harness.run(&agents);
        seeds_run += 1;
        if !report.ok() {
            let detail = report
                .trace
                .failure
                .clone()
                .unwrap_or_else(|| "unknown failure".into());
            eprintln!(
                "adversarial sweep FAILURE seed={seed} detail={detail} fingerprint={}",
                report.trace.fingerprint()
            );
            failures.push((seed, detail));
            // Keep going so one flaky seed doesn't hide others, but CI will
            // still fail the job on any failure.
        }
    }

    SweepReport {
        seeds_run,
        failures,
        elapsed: started.elapsed(),
        hit_budget,
    }
}
