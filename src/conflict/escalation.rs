//! Builds the on-chain dispute escalation payload for a [`Conflict`] that
//! [`crate::conflict::resolver::resolve_conflict`] could not settle
//! off-chain.
//!
//! Per the architecture (see the crate README), an unresolved conflict must
//! escalate to the `dispute-resolver` Soroban contract in
//! `stellarconduit-contracts`, whose entry point is:
//!
//! ```ignore
//! pub fn raise_dispute(
//!     env: Env,
//!     initiator: Address,
//!     respondent: Address,
//!     tx_id: BytesN<32>,
//!     proof: RelayChainProof,
//! ) -> Result<u64, ContractError>
//! ```
//!
//! This module only *builds and validates* that payload — see
//! [`DisputeEscalation`] — and `crate::storage::db::SyncEngineDb` persists it
//! durably so a relay node (which owns the live Soroban RPC connection, not
//! this crate) can submit it whenever it next has connectivity. Actually
//! calling `raise_dispute` is out of scope here.

use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::conflict::detector::Conflict;
use crate::errors::SyncEngineError;
use crate::stellar_address::pubkey_to_stellar_address;

/// Everything this device knows about one side of a [`Conflict`] that's
/// needed to build a [`DisputeEscalation`] — the escalation counterpart to
/// `crate::conflict::resolver::ConflictEvidence`'s per-side fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscalationInput {
    /// Must match one of `conflict.envelope_a` / `conflict.envelope_b`.
    pub message_id: [u8; 32],
    /// The raw ed25519 key of the device that originally created this
    /// envelope (`TransactionEnvelope.origin_pubkey`), converted to a
    /// Stellar `G...` address via [`pubkey_to_stellar_address`].
    pub origin_pubkey: [u8; 32],
    /// When *this device* first observed this envelope, per its own local
    /// clock. Used only to order initiator vs respondent (see
    /// [`build_escalation`]) — never compared across devices.
    pub first_seen_locally_at: u64,
    /// A relay-chain proof corroborating this envelope, carried into the
    /// escalation so on-chain arbitration has cryptographic evidence to
    /// weigh, not just this device's say-so.
    pub proof: RelayChainProof,
}

/// A fully-formed, ready-to-submit payload for the `dispute-resolver`
/// contract's `raise_dispute` entry point.
#[derive(Debug, Clone, PartialEq)]
pub struct DisputeEscalation {
    /// Stellar `G...` StrKey address of the side treated as having raised
    /// the dispute.
    pub initiator: String,
    /// Stellar `G...` StrKey address of the other side.
    pub respondent: String,
    /// The disputed envelope's `message_id`, standing in for `tx_id` as
    /// `raise_dispute` expects it — always the **initiator**'s envelope,
    /// matching `proof` below.
    pub tx_id: [u8; 32],
    /// Corroborating relay-chain proof for `tx_id`.
    pub proof: RelayChainProof,
}

/// Build a [`DisputeEscalation`] for `conflict` from the two sides' evidence.
///
/// # Choosing initiator vs respondent
///
/// This crate never has a global view of the mesh, so there is no
/// universally-agreed notion of "which envelope came first". The one
/// ordering this device *can* independently attest to is when it locally
/// first observed each envelope — so the side with the earlier
/// `first_seen_locally_at` is treated as the initiator. Ties fall back to
/// `envelope_a`, matching `conflict`'s own arbitrary-but-deterministic
/// ordering.
///
/// # Errors
///
/// Returns [`SyncEngineError::InvalidEnvelope`] if `envelope_a`/`envelope_b`'s
/// `message_id`s don't match `conflict.envelope_a`/`conflict.envelope_b` —
/// this is a caller bug (mismatched evidence passed in), not a runtime
/// condition worth retrying.
pub fn build_escalation(
    conflict: &Conflict,
    envelope_a: &EscalationInput,
    envelope_b: &EscalationInput,
) -> Result<DisputeEscalation, SyncEngineError> {
    if envelope_a.message_id != conflict.envelope_a || envelope_b.message_id != conflict.envelope_b
    {
        return Err(SyncEngineError::InvalidEnvelope(format!(
            "escalation evidence message ids ({}, {}) do not match conflict envelopes ({}, {}) \
             for account {} sequence {}",
            hex::encode(envelope_a.message_id),
            hex::encode(envelope_b.message_id),
            hex::encode(conflict.envelope_a),
            hex::encode(conflict.envelope_b),
            conflict.source_account,
            conflict.sequence,
        )));
    }

    let (initiator, respondent) =
        if envelope_a.first_seen_locally_at <= envelope_b.first_seen_locally_at {
            (envelope_a, envelope_b)
        } else {
            (envelope_b, envelope_a)
        };

    Ok(DisputeEscalation {
        initiator: pubkey_to_stellar_address(&initiator.origin_pubkey),
        respondent: pubkey_to_stellar_address(&respondent.origin_pubkey),
        tx_id: initiator.message_id,
        proof: initiator.proof.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::detector::conflicts_between;
    use crate::conflict::detector::QueuedSlot;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn base_conflict() -> Conflict {
        let a = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [1u8; 32],
        };
        let b = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [2u8; 32],
        };
        conflicts_between(&a, &b).unwrap()
    }

    fn proof_for(tx_id: &[u8; 32]) -> RelayChainProof {
        let key = SigningKey::generate(&mut OsRng);
        RelayChainProof::sign(&key, tx_id, &[9u8; 32], 101)
    }

    fn input(
        message_id: [u8; 32],
        origin_pubkey: [u8; 32],
        first_seen_locally_at: u64,
    ) -> EscalationInput {
        EscalationInput {
            message_id,
            origin_pubkey,
            first_seen_locally_at,
            proof: proof_for(&message_id),
        }
    }

    #[test]
    fn test_build_escalation_produces_valid_addresses() {
        let conflict = base_conflict();
        let envelope_a = input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = input(conflict.envelope_b, [20u8; 32], 2000);

        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();

        assert_eq!(escalation.initiator, pubkey_to_stellar_address(&[10u8; 32]));
        assert_eq!(
            escalation.respondent,
            pubkey_to_stellar_address(&[20u8; 32])
        );
        assert!(escalation.initiator.starts_with('G'));
        assert!(escalation.respondent.starts_with('G'));
        assert_ne!(escalation.initiator, escalation.respondent);
        assert_eq!(escalation.tx_id, conflict.envelope_a);
    }

    #[test]
    fn test_build_escalation_picks_earlier_seen_side_as_initiator() {
        let conflict = base_conflict();
        // envelope_b was seen locally *before* envelope_a, so it must become
        // the initiator even though it's conflict.envelope_b.
        let envelope_a = input(conflict.envelope_a, [10u8; 32], 5000);
        let envelope_b = input(conflict.envelope_b, [20u8; 32], 1000);

        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();

        assert_eq!(escalation.tx_id, conflict.envelope_b);
        assert_eq!(escalation.initiator, pubkey_to_stellar_address(&[20u8; 32]));
        assert_eq!(
            escalation.respondent,
            pubkey_to_stellar_address(&[10u8; 32])
        );
    }

    #[test]
    fn test_build_escalation_tie_defaults_to_envelope_a_as_initiator() {
        let conflict = base_conflict();
        let envelope_a = input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = input(conflict.envelope_b, [20u8; 32], 1000);

        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();

        assert_eq!(escalation.tx_id, conflict.envelope_a);
    }

    #[test]
    fn test_build_escalation_rejects_mismatched_evidence() {
        let conflict = base_conflict();
        // envelope_a's message_id doesn't match conflict.envelope_a at all.
        let wrong_envelope_a = input([99u8; 32], [10u8; 32], 1000);
        let envelope_b = input(conflict.envelope_b, [20u8; 32], 2000);

        let result = build_escalation(&conflict, &wrong_envelope_a, &envelope_b);
        assert!(matches!(result, Err(SyncEngineError::InvalidEnvelope(_))));
    }

    #[test]
    fn test_build_escalation_proof_matches_initiator() {
        let conflict = base_conflict();
        let envelope_a = input(conflict.envelope_a, [10u8; 32], 1000);
        let envelope_b = input(conflict.envelope_b, [20u8; 32], 2000);
        let expected_proof = envelope_a.proof.clone();

        let escalation = build_escalation(&conflict, &envelope_a, &envelope_b).unwrap();
        assert_eq!(escalation.proof, expected_proof);
    }
}
