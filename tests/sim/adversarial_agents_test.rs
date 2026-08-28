//! Required `#070` determinism tests + regression from the adversarial sweep.

use stellarconduit_sync_engine::conflict::{detect_conflicts, detect_nway_conflicts, QueuedSlot};
use stellarconduit_sync_engine::sim::{
    AdversarialAgent, ForgedProofAgent, RaceAgent, ReplayAgent, SimConfig, SimHarness,
};

fn run_twice(seed: u64, agent: &dyn AdversarialAgent) -> (String, String) {
    let agents = [agent];
    let mut a = SimHarness::new(SimConfig::default().with_seed(seed));
    let mut b = SimHarness::new(SimConfig::default().with_seed(seed));
    let ra = a.run(&agents);
    let rb = b.run(&agents);
    assert!(ra.ok(), "seed {seed} left: {:?}", ra.trace.failure);
    assert!(rb.ok(), "seed {seed} right: {:?}", rb.trace.failure);
    (ra.trace.fingerprint(), rb.trace.fingerprint())
}

#[test]
fn test_forged_proof_agent_is_deterministic_given_seed() {
    let (fa, fb) = run_twice(0xF0_F6_ED_01, &ForgedProofAgent);
    assert_eq!(fa, fb);
    // Different seed ⇒ different fingerprint (agent mixes RNG into ids).
    let (other, _) = run_twice(0xF0_F6_ED_02, &ForgedProofAgent);
    assert_ne!(fa, other);
}

#[test]
fn test_replay_agent_is_deterministic_given_seed() {
    let (fa, fb) = run_twice(0x4E_51_A7_01, &ReplayAgent);
    assert_eq!(fa, fb);
    let (other, _) = run_twice(0x4E_51_A7_02, &ReplayAgent);
    assert_ne!(fa, other);
}

#[test]
fn test_race_agent_is_deterministic_given_seed() {
    let (fa, fb) = run_twice(0x4A_CE_00_01, &RaceAgent);
    assert_eq!(fa, fb);
    let (other, _) = run_twice(0x4A_CE_00_02, &RaceAgent);
    assert_ne!(fa, other);
}

/// Regression derived from the adversarial race sweep (`#070`):
/// `detect_conflicts` / `detect_nway_conflicts` used to return results in
/// `HashMap` iteration order, so the same logical slot set produced
/// different `Vec` orderings depending on insertion permutation. That
/// breaks seeded simulation reproducibility (the core `#049` contract the
/// Byzantine agents depend on). After the fix, every permutation yields
/// an identical conflict list.
#[test]
fn test_race_agent_detect_conflicts_output_is_insertion_order_independent() {
    let account = "GRACE";
    let sequence = 7i64;
    let ids: [[u8; 32]; 3] = [[1u8; 32], [2u8; 32], [3u8; 32]];
    let mk = |order: [usize; 3]| -> Vec<QueuedSlot> {
        order
            .iter()
            .map(|&i| QueuedSlot {
                source_account: account.into(),
                sequence,
                message_id: ids[i],
            })
            .collect()
    };

    let permutations = [
        [0, 1, 2],
        [2, 1, 0],
        [1, 0, 2],
        [2, 0, 1],
        [0, 2, 1],
        [1, 2, 0],
    ];
    let baseline_pairs = detect_conflicts(&mk(permutations[0]));
    let baseline_nway = detect_nway_conflicts(&mk(permutations[0]));
    assert_eq!(baseline_pairs.len(), 3);
    assert_eq!(baseline_nway.len(), 1);

    for perm in permutations {
        let slots = mk(perm);
        assert_eq!(
            detect_conflicts(&slots),
            baseline_pairs,
            "pairwise conflicts changed under insertion order {perm:?}"
        );
        assert_eq!(
            detect_nway_conflicts(&slots),
            baseline_nway,
            "n-way conflicts changed under insertion order {perm:?}"
        );
    }
}

#[test]
fn test_all_three_agents_together_are_deterministic() {
    let agents: [&dyn AdversarialAgent; 3] = [&ForgedProofAgent, &ReplayAgent, &RaceAgent];
    let seed = 0x70_70_70_70u64;
    let mut a = SimHarness::new(SimConfig::default().with_seed(seed));
    let mut b = SimHarness::new(SimConfig::default().with_seed(seed));
    let ra = a.run(&agents);
    let rb = b.run(&agents);
    assert!(ra.ok(), "{:?}", ra.trace.failure);
    assert!(rb.ok(), "{:?}", rb.trace.failure);
    assert_eq!(ra.trace.fingerprint(), rb.trace.fingerprint());
}
