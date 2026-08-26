//! Agent that races two conflicting envelopes into detection at the same
//! simulated tick under every deterministic arrival permutation.

use rand::seq::SliceRandom;
use rand::RngCore;

use crate::clock::Clock;
use crate::conflict::{detect_conflicts, detect_nway_conflicts, QueuedSlot};
use crate::sim::agents::{AdversarialAgent, AgentCtx, AgentOutcome};

/// Schedules two distinct envelopes for the same (account, sequence) slot
/// with adversarial arrival orderings. A correct detector must:
///
/// 1. Report exactly one pairwise conflict (and one N-way conflict) no
///    matter the arrival permutation.
/// 2. Produce a **byte-identical** conflict list for every permutation —
///    i.e. output order must not depend on `HashMap` insertion order.
///
/// Requirement (2) is what the adversarial sweep actually broke before
/// `detect_conflicts` / `detect_nway_conflicts` started sorting their
/// results; see `test_race_agent_detect_conflicts_output_is_insertion_order_independent`.
#[derive(Debug, Default, Clone, Copy)]
pub struct RaceAgent;

impl RaceAgent {
    fn slot(account: &str, sequence: i64, message_id: [u8; 32]) -> QueuedSlot {
        QueuedSlot {
            source_account: account.to_string(),
            sequence,
            message_id,
        }
    }
}

impl AdversarialAgent for RaceAgent {
    fn name(&self) -> &'static str {
        "race"
    }

    fn act(&self, ctx: &mut AgentCtx<'_>) -> AgentOutcome {
        let account = ctx.world.account.clone();
        let sequence = ctx.world.sequence;
        let at = ctx.clock.now_secs();

        // Three-way race: more interesting for order-stability than a pair,
        // because HashMap group iteration + pair enumeration used to yield
        // permutation-dependent `Vec` order across the wider conflict set.
        let mut ids = Vec::with_capacity(3);
        for _ in 0..3 {
            let mut id = [0u8; 32];
            ctx.rng.fill_bytes(&mut id);
            // Keep ids unique.
            while ids.iter().any(|e| e == &id) {
                ctx.rng.fill_bytes(&mut id);
            }
            ids.push(id);
        }
        ids.sort(); // canonical label order for the trace only

        let slots_canon: Vec<QueuedSlot> = ids
            .iter()
            .map(|id| Self::slot(&account, sequence, *id))
            .collect();

        // Permute arrival order deterministically from the harness RNG.
        let mut order = slots_canon.clone();
        order.shuffle(ctx.rng);
        let perm_label: String = order
            .iter()
            .map(|s| hex::encode(s.message_id))
            .collect::<Vec<_>>()
            .join(",");

        // Split-brain: device-0 sees first arrival, device-1 the rest, then
        // merge — models two relays accepting conflicting envelopes at the
        // "closest-possible" simulated timing (same `at` tick).
        {
            let d0 = ctx.world.ensure_device("race-0");
            d0.slots.clear();
            d0.slots.push(order[0].clone());
        }
        {
            let d1 = ctx.world.ensure_device("race-1");
            d1.slots.clear();
            d1.slots.extend(order[1..].iter().cloned());
        }

        let merged = ctx.world.merged_slots();
        let conflicts = detect_conflicts(&merged);
        let nway = detect_nway_conflicts(&merged);

        // Re-run with the opposite permutation; results must match exactly.
        let mut opposite = slots_canon.clone();
        opposite.reverse();
        let conflicts_rev = detect_conflicts(&opposite);
        let nway_rev = detect_nway_conflicts(&opposite);

        let expected_pairs = 3; // C(3,2) = 3
        let pairs_ok = conflicts.len() == expected_pairs && conflicts_rev.len() == expected_pairs;
        let nway_ok = nway.len() == 1
            && nway_rev.len() == 1
            && nway[0].message_ids.len() == 3
            && nway_rev[0].message_ids.len() == 3;
        let order_stable = conflicts == conflicts_rev && nway == nway_rev;

        ctx.trace.record(
            at,
            self.name(),
            "race_conflicts_detected",
            format!(
                "perm={perm_label} pairs={} nway={} order_stable={order_stable}",
                conflicts.len(),
                nway.len()
            ),
        );

        if !(pairs_ok && nway_ok) {
            let msg = format!(
                "race missed conflicts: pairs={} (want {expected_pairs}) nway_ok={nway_ok}",
                conflicts.len()
            );
            ctx.trace.fail(&msg);
            return AgentOutcome::InvariantViolation { summary: msg };
        }

        if !order_stable {
            let msg = "detect_conflicts/detect_nway_conflicts output depends on slot \
                       insertion order (HashMap iteration) — breaks seeded reproducibility"
                .to_string();
            ctx.trace.fail(&msg);
            return AgentOutcome::InvariantViolation { summary: msg };
        }

        AgentOutcome::Defended {
            summary: format!(
                "race detected {expected_pairs} pairs + 1 n-way conflict; output order-stable"
            ),
        }
    }
}
