//! Bounded adversarial seed sweep for CI (`#070`).
//!
//! Default: 256 seeds or 30s, whichever comes first. Override with
//! `ADVERSARIAL_SWEEP_SEEDS` / `ADVERSARIAL_SWEEP_BUDGET_SECS` for a larger
//! nightly run.

use stellarconduit_sync_engine::sim::{run_adversarial_sweep, SweepConfig};

#[test]
fn adversarial_sweep_bounded() {
    let report = run_adversarial_sweep(SweepConfig::from_env_or_default());
    eprintln!(
        "adversarial sweep: seeds_run={} elapsed={:?} hit_budget={} failures={}",
        report.seeds_run,
        report.elapsed,
        report.hit_budget,
        report.failures.len()
    );
    assert!(report.seeds_run > 0, "sweep must execute at least one seed");
    assert!(
        report.ok(),
        "adversarial sweep failures: {:?}",
        report.failures
    );
}
