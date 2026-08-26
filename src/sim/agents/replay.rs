//! Agent that replays previously-valid relay observations out of context.

use ed25519_dalek::SigningKey;
use rand::RngCore;
use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::clock::Clock;
use crate::conflict::{
    conflicts_between, resolve_conflict, ConflictEvidence, QueuedSlot, RelayObservation,
};
use crate::errors::SyncEngineError;
use crate::sim::agents::{AdversarialAgent, AgentCtx, AgentOutcome};

/// Captures a valid observation, then replays it against the wrong sequence
/// and after its TTL — neither replay may decide a conflict.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReplayAgent;

impl ReplayAgent {
    fn key_from_rng(rng: &mut impl RngCore) -> SigningKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }
}

impl AdversarialAgent for ReplayAgent {
    fn name(&self) -> &'static str {
        "replay"
    }

    fn act(&self, ctx: &mut AgentCtx<'_>) -> AgentOutcome {
        let account = ctx.world.account.clone();
        let sequence = ctx.world.sequence;
        let at = ctx.clock.now_secs();

        let mut id_a = [0x11; 32];
        let mut id_b = [0x22; 32];
        ctx.rng.fill_bytes(&mut id_a);
        ctx.rng.fill_bytes(&mut id_b);
        // Ensure they differ even if the RNG collided (astronomically unlikely).
        if id_a == id_b {
            id_b[0] ^= 0xff;
        }

        let slot_a = QueuedSlot {
            source_account: account.clone(),
            sequence,
            message_id: id_a,
        };
        let slot_b = QueuedSlot {
            source_account: account.clone(),
            sequence,
            message_id: id_b,
        };
        let conflict = conflicts_between(&slot_a, &slot_b).expect("distinct ids conflict");

        let relay = Self::key_from_rng(ctx.rng);
        let chain = [9u8; 32];
        let fresh = RelayObservation {
            relay_pubkey: relay.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(&relay, &id_a, &chain, sequence as u64),
        };

        // Record acceptance time for TTL reasoning.
        let mid = hex::encode(id_a);
        ctx.world.observation_accepted_at.insert(mid.clone(), at);
        ctx.world
            .ensure_device("replay-victim")
            .observations
            .insert(mid, vec![fresh.clone()]);

        // Advance simulated time past the observation TTL.
        let ttl = ctx.world.observation_ttl_secs;
        ctx.clock.advance(ttl.saturating_add(1));
        let later = ctx.clock.now_secs();

        // Replay 1: same proof bytes, but conflict sequence shifted — the
        // resolver must drop it via the sequence filter.
        let wrong_seq_conflict = {
            let slot_a2 = QueuedSlot {
                source_account: account.clone(),
                sequence: sequence + 1,
                message_id: id_a,
            };
            let slot_b2 = QueuedSlot {
                source_account: account.clone(),
                sequence: sequence + 1,
                message_id: id_b,
            };
            conflicts_between(&slot_a2, &slot_b2).expect("still a conflict")
        };

        let replayed_wrong_seq = ConflictEvidence {
            envelope_a_timestamp: at,
            envelope_b_timestamp: at,
            envelope_a_observations: vec![fresh.clone()],
            envelope_b_observations: Vec::new(),
        };

        let wrong_seq_ok = matches!(
            resolve_conflict(&wrong_seq_conflict, &replayed_wrong_seq),
            Err(SyncEngineError::UnresolvedConflict(_))
        );

        // Replay 2: same sequence (still cryptographically valid) but past
        // TTL. Today's resolver has no freshness check — so a lone stale
        // observation still fails MIN_QUORUM, which is the property we
        // assert here. If a future change awarded a win on one stale proof,
        // this agent trips.
        let stale_evidence = ConflictEvidence {
            envelope_a_timestamp: at,
            envelope_b_timestamp: at,
            envelope_a_observations: vec![fresh],
            envelope_b_observations: Vec::new(),
        };
        let stale_result = resolve_conflict(&conflict, &stale_evidence);
        let stale_ok = matches!(stale_result, Err(SyncEngineError::UnresolvedConflict(_)));

        ctx.trace.record(
            later,
            self.name(),
            "replay_attempts",
            format!(
                "wrong_seq_defended={wrong_seq_ok} stale_lone_proof_unresolved={stale_ok} ttl={ttl}"
            ),
        );

        if wrong_seq_ok && stale_ok {
            AgentOutcome::Defended {
                summary: "stale/out-of-sequence replays did not resolve a conflict".into(),
            }
        } else {
            let msg =
                format!("replay slipped through: wrong_seq_ok={wrong_seq_ok} stale_ok={stale_ok}");
            ctx.trace.fail(&msg);
            AgentOutcome::InvariantViolation { summary: msg }
        }
    }
}
