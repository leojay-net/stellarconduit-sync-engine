//! Agent that forges / tampers relay-chain proofs and injects them into
//! conflict evidence — the direct stress test for `#046`-style verification
//! and for today's signature checks in [`resolve_conflict`].

use ed25519_dalek::SigningKey;
use rand::RngCore;
use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::clock::Clock;
use crate::conflict::{
    conflicts_between, resolve_conflict, ConflictEvidence, QueuedSlot, RelayObservation,
};
use crate::errors::SyncEngineError;
use crate::sim::agents::{AdversarialAgent, AgentCtx, AgentOutcome};

/// Crafts three classes of bad proofs and asserts none of them can win a
/// conflict against an honest quorum.
#[derive(Debug, Default, Clone, Copy)]
pub struct ForgedProofAgent;

impl ForgedProofAgent {
    fn key_from_rng(rng: &mut impl RngCore) -> SigningKey {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    fn message_id(tag: u8, rng: &mut impl RngCore) -> [u8; 32] {
        let mut id = [tag; 32];
        // Mix in RNG bytes so different seeds produce different ids while
        // remaining fully determined by the seed.
        let mut mix = [0u8; 32];
        rng.fill_bytes(&mut mix);
        for (dst, src) in id.iter_mut().zip(mix.iter()) {
            *dst ^= src;
        }
        id
    }
}

impl AdversarialAgent for ForgedProofAgent {
    fn name(&self) -> &'static str {
        "forged_proof"
    }

    fn act(&self, ctx: &mut AgentCtx<'_>) -> AgentOutcome {
        let sequence = ctx.world.sequence;
        let account = ctx.world.account.clone();
        let at = ctx.clock.now_secs();

        let honest_a = Self::message_id(0xA1, ctx.rng);
        let honest_b = Self::message_id(0xB2, ctx.rng);

        let slot_a = QueuedSlot {
            source_account: account.clone(),
            sequence,
            message_id: honest_a,
        };
        let slot_b = QueuedSlot {
            source_account: account.clone(),
            sequence,
            message_id: honest_b,
        };
        let conflict = conflicts_between(&slot_a, &slot_b)
            .expect("distinct message ids on the same slot must conflict");

        // Honest quorum for side A (2 distinct relays — the MIN_QUORUM floor).
        let relay1 = Self::key_from_rng(ctx.rng);
        let relay2 = Self::key_from_rng(ctx.rng);
        let chain = {
            let mut h = [0u8; 32];
            ctx.rng.fill_bytes(&mut h);
            h
        };
        let honest_obs = vec![
            RelayObservation {
                relay_pubkey: relay1.verifying_key().to_bytes(),
                proof: RelayChainProof::sign(&relay1, &honest_a, &chain, sequence as u64),
            },
            RelayObservation {
                relay_pubkey: relay2.verifying_key().to_bytes(),
                proof: RelayChainProof::sign(&relay2, &honest_a, &chain, sequence as u64),
            },
        ];

        // --- Attack 1: flip bits in a valid signature (classic tamper). ---
        let mut tampered = honest_obs[0].clone();
        tampered.proof.signature[0] ^= 0xff;
        tampered.proof.signature[31] ^= 0xaa;

        // --- Attack 2: valid signature over a *different* chain_hash, then
        //     present it unchanged — verify must fail once chain_hash on the
        //     struct doesn't match what was signed. We mutate chain_hash
        //     *after* signing so the signature is over the old hash. ---
        let mut mutated_hash = honest_obs[1].clone();
        mutated_hash.proof.chain_hash[0] ^= 0x5a;

        // --- Attack 3: proof signed for envelope A, attached as evidence
        //     for envelope B (cross-wiring / confused-deputy). ---
        let cross_wired = honest_obs[0].clone();

        // --- Attack 4: adversary-minted "proof" with a fresh keypair that
        //     actually verifies for B — Sybil single-relay support. Alone it
        //     must not beat A's quorum of 2. ---
        let sybil = Self::key_from_rng(ctx.rng);
        let sybil_obs = RelayObservation {
            relay_pubkey: sybil.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(&sybil, &honest_b, &chain, sequence as u64),
        };

        let evidence = ConflictEvidence {
            envelope_a_timestamp: at,
            envelope_b_timestamp: at.saturating_add(1),
            envelope_a_observations: {
                let mut v = honest_obs;
                v.push(tampered.clone());
                v.push(mutated_hash.clone());
                v
            },
            envelope_b_observations: vec![cross_wired.clone(), sybil_obs.clone()],
        };

        ctx.trace.record(
            at,
            self.name(),
            "injected_forgeries",
            format!(
                "tampered_sig={} mutated_hash={} cross_wired={} sybil={}",
                hex::encode(tampered.proof.signature),
                hex::encode(mutated_hash.proof.chain_hash),
                hex::encode(cross_wired.relay_pubkey),
                hex::encode(sybil_obs.relay_pubkey),
            ),
        );

        match resolve_conflict(&conflict, &evidence) {
            Ok(winner) if winner == honest_a => {
                // Expected: A keeps the honest quorum; forgeries add nothing
                // to B and do not poison A.
                ctx.trace.record(
                    at,
                    self.name(),
                    "forged_proof_rejected",
                    format!("winner={}", hex::encode(winner)),
                );
                AgentOutcome::Defended {
                    summary: "forged/tampered proofs did not overturn honest quorum".into(),
                }
            }
            Ok(winner) => {
                let msg = format!(
                    "forged proofs caused unexpected winner {}",
                    hex::encode(winner)
                );
                ctx.trace.fail(&msg);
                AgentOutcome::InvariantViolation { summary: msg }
            }
            Err(SyncEngineError::UnresolvedConflict(_)) => {
                // Also acceptable: forgeries confused the count into a tie /
                // below quorum. Must *not* award B.
                ctx.trace.record(
                    at,
                    self.name(),
                    "forged_proof_unresolved",
                    "resolver refused to decide under forged evidence",
                );
                AgentOutcome::Defended {
                    summary: "resolver left conflict unresolved rather than trusting forgeries"
                        .into(),
                }
            }
            Err(other) => {
                let msg = format!("unexpected error under forged evidence: {other}");
                ctx.trace.fail(&msg);
                AgentOutcome::InvariantViolation { summary: msg }
            }
        }
    }
}
