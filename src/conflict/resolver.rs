//! Deterministic off-chain resolution of a detected [`Conflict`].
//!
//! This is the flagship hard problem of the sync engine: a decision procedure
//! that lets every honest node in the mesh independently reach the same
//! conclusion about which of two conflicting envelopes wins, using only
//! evidence that plausibly propagated to it, with no coordination round.
//!
//! `stellarconduit_core::message::relay_proof::RelayChainProof` proves that
//! *some* relay signed off on `(tx_id, chain_hash, sequence)`, but carries no
//! signer identity of its own — verifying it requires already knowing which
//! `VerifyingKey` to check, and counting distinct relays (required for any
//! Sybil-resistant quorum reasoning) requires knowing each proof's signer.
//! This module closes that gap by requiring callers to pair each proof with
//! the relay's known pubkey at collection time (see [`RelayObservation`]) —
//! e.g. from `stellarconduit_core::peer::identity::PeerIdentity`, which a node
//! already tracks per-peer.
//!
//! Conflicts this algorithm cannot settle remain unresolved off-chain and must
//! go to on-chain arbitration via the `dispute-resolver` Soroban contract in
//! `stellarconduit-contracts`.
//!
//! # Beyond two envelopes
//!
//! [`resolve_nway_conflict`] extends the same relay-quorum evidence and rules
//! above to an [`crate::conflict::detector::NWayConflict`] with three or more
//! candidates, computed once over the whole set rather than via independent
//! pairwise calls to [`resolve_conflict`]. That distinction matters: judging
//! an N-way conflict as a series of pairwise calls can produce a
//! non-transitive outcome (A beats B, B beats C, C beats A), since each
//! pairwise call only ever sees two of the candidates. `resolve_nway_conflict`
//! ranks every candidate's distinct-relay count against the whole set in one
//! pass, so there is exactly one ranking and no such contradiction is
//! possible.

use std::collections::HashSet;

use ed25519_dalek::VerifyingKey;
use stellarconduit_core::message::relay_proof::RelayChainProof;

use crate::conflict::detector::{Conflict, NWayConflict};
use crate::conflict::vrf_tiebreak::{
    verify_tiebreak_with_evaluator, RelayVrfIdentity, TiebreakOutcome,
};
use crate::errors::SyncEngineError;

/// Minimum number of *distinct* relays whose valid, verified relay-chain
/// proofs must corroborate a side before that side is even eligible to win.
///
/// This is the Sybil-resistance backstop: an attacker holding a single relay
/// keypair can mint arbitrarily many identical-looking proofs, but they all
/// collapse to one entry in the per-side relay set (see
/// [`count_distinct_valid_relays`]). Requiring at least two distinct relays
/// means a single relay — honest or compromised — can never win a conflict
/// outright, even against a side with zero evidence.
const MIN_QUORUM: usize = 2;

/// A single relay's cryptographically verifiable attestation that it relayed
/// a specific envelope, paired with the relay's known public key.
///
/// [`RelayChainProof`] alone carries no signer identity (see the module
/// docs), so callers must supply the `relay_pubkey` they associate with this
/// proof — normally the identity already recorded on the local peer/relay
/// table at the point the proof was collected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayObservation {
    pub relay_pubkey: [u8; 32],
    pub proof: RelayChainProof,
}

/// Everything a node has locally gathered about both sides of a [`Conflict`]
/// beyond the conflict's own account/sequence/envelope-id bookkeeping.
///
/// This crate never has a global view of the mesh — only whatever gossip
/// plausibly reached this node — so evidence is supplied explicitly by the
/// caller rather than fetched by [`resolve_conflict`] itself. That keeps the
/// function pure and its output fully determined by its arguments, which is
/// what makes it possible for every node to compute the identical result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConflictEvidence {
    /// `TransactionEnvelope.timestamp` as originally signed by the sender of
    /// `conflict.envelope_a`. Recorded for audit/escalation context (see
    /// [`resolve_conflict`]'s doc comment for why it is not decisive).
    pub envelope_a_timestamp: u64,
    pub envelope_b_timestamp: u64,
    /// Every relay observation that plausibly propagated to this node for
    /// the side identified by `conflict.envelope_a`. Order doesn't matter and
    /// duplicate/repeated entries from the same relay are harmless — they
    /// collapse during dedup.
    pub envelope_a_observations: Vec<RelayObservation>,
    pub envelope_b_observations: Vec<RelayObservation>,
}

/// Filter `observations` down to those that are valid evidence for `tx_id`
/// under `conflict`'s sequence, and return the set of distinct relay pubkeys
/// among the survivors.
///
/// An observation is excluded (not counted as evidence at all) unless both:
/// - `proof.sequence == conflict.sequence` — a proof harvested for a
///   different slot doesn't speak to this conflict, regardless of whether
///   its own signature is otherwise valid;
/// - `proof.verify(relay_pubkey, tx_id)` succeeds — the signature must
///   actually be from `relay_pubkey` over this exact `(tx_id, chain_hash,
///   sequence)` tuple. A malformed pubkey or a signature that doesn't verify
///   is dropped rather than trusted.
///
/// Distinct relay pubkeys are counted, not raw proof count, so that an
/// attacker resubmitting the same relay's proof many times gains nothing.
fn count_distinct_valid_relays(
    observations: &[RelayObservation],
    conflict_sequence: i64,
    tx_id: &[u8; 32],
) -> HashSet<[u8; 32]> {
    let expected_sequence = conflict_sequence as u64;
    observations
        .iter()
        .filter(|obs| obs.proof.sequence == expected_sequence)
        .filter(|obs| {
            VerifyingKey::from_bytes(&obs.relay_pubkey)
                .map(|key| obs.proof.verify(&key, tx_id))
                .unwrap_or(false)
        })
        .map(|obs| obs.relay_pubkey)
        .collect()
}

/// Attempt to resolve `conflict` off-chain, returning the `message_id` of the
/// envelope determined to be valid.
///
/// # Decision procedure
///
/// 1. **Validate, don't trust.** For each side, discard any relay observation
///    whose proof doesn't match `conflict`'s sequence or doesn't verify
///    against the paired relay pubkey for that side's envelope id (see
///    [`count_distinct_valid_relays`]).
/// 2. **Count distinct relays, not proofs.** The surviving observations for
///    each side are deduplicated by relay pubkey. This is the Sybil-resistance
///    mechanism required by the issue: a single relay keypair can mint
///    unlimited proofs, but they all count once.
/// 3. **Quorum + strict majority.** Side A wins iff it has at least
///    [`MIN_QUORUM`] distinct corroborating relays *and* strictly more than
///    side B (symmetrically for B). Both conditions must hold:
///    - the quorum floor means a lone relay — even an honest, perfectly valid
///      one — can never win a conflict outright, satisfying "a single relay
///      lying or being compromised must not be enough to win a conflict";
///    - the strict-majority requirement means a tie at any count (0-vs-0,
///      2-vs-2, 3-vs-3, ...) is *never* decided by this function — it falls
///      through to `Err(UnresolvedConflict)` rather than an arbitrary guess.
///
///    A **quorum-met tie** (both sides ≥ [`MIN_QUORUM`] and exactly equal) is
///    the one case where a further, last-resort criterion applies: the VRF
///    tie-break of issue #067. `resolve_conflict` itself stays pure and still
///    returns `Err` for it; [`resolve_conflict_with_tiebreak`] is the entry
///    point that consults the tie-break, and [`quorum_standing`] exposes the
///    distinction. Every other `Err` from here (under-evidenced, lone relay)
///    escalates on-chain with no tie-break.
/// 4. **Envelope timestamps are recorded, not decisive.** `evidence`'s
///    timestamps are included in the `UnresolvedConflict` message (useful
///    context for the on-chain escalation path) but never influence which
///    side wins or break a tie. A timestamp is self-reported by the
///    envelope's origin — exactly the kind of value an attacker crafting a
///    conflicting envelope is free to backdate — so treating it as evidence
///    would violate the "no trusted third party / cryptographically
///    verifiable evidence only" constraint this algorithm must satisfy. Only
///    the Sybil-resistant relay quorum computed in steps 1–3 is
///    cryptographically anchored, so only it decides.
///
/// Because every step is a pure function of `conflict` and `evidence` — no
/// wall-clock reads, no randomness, no network round-trip — every node that
/// receives the same evidence computes the same result.
pub fn resolve_conflict(
    conflict: &Conflict,
    evidence: &ConflictEvidence,
) -> Result<[u8; 32], SyncEngineError> {
    let (standing, n_a, n_b) = standing_with_counts(conflict, evidence);
    match standing {
        QuorumStanding::Decisive(winner) => Ok(winner),
        QuorumStanding::QuorumTie { .. } | QuorumStanding::Insufficient { .. } => {
            Err(SyncEngineError::UnresolvedConflict(format!(
                "conflict on account {} sequence {} between {} (timestamp {}, {} verified distinct \
                 relay(s)) and {} (timestamp {}, {} verified distinct relay(s)) could not be \
                 resolved off-chain: a winning side needs at least {} distinct corroborating \
                 relays and strictly more than the other side",
                conflict.source_account,
                conflict.sequence,
                hex::encode(conflict.envelope_a),
                evidence.envelope_a_timestamp,
                n_a,
                hex::encode(conflict.envelope_b),
                evidence.envelope_b_timestamp,
                n_b,
                MIN_QUORUM,
            )))
        }
    }
}

/// How `conflict` stands on relay-quorum evidence alone — the result of steps
/// 1–3 of [`resolve_conflict`]'s decision procedure, exposed so the VRF
/// tie-break layer (issue #067) can tell a genuine quorum-met tie (its only
/// valid trigger) apart from a merely under-evidenced conflict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumStanding {
    /// One side has ≥ [`MIN_QUORUM`] distinct relays *and* strictly more than
    /// the other. [`resolve_conflict`] returns this `message_id` outright and
    /// the tie-break is never consulted.
    Decisive([u8; 32]),
    /// Both sides reached [`MIN_QUORUM`] and have the *same* distinct-relay
    /// count. This — and only this — is where a VRF tie-break may be applied.
    QuorumTie {
        /// The shared distinct-relay count of the two sides.
        distinct_relays_each: usize,
    },
    /// At least one side is below [`MIN_QUORUM`]. Escalate on-chain; a
    /// tie-break here would be deciding a conflict nobody corroborated.
    Insufficient {
        /// Distinct verified relays for `conflict.envelope_a`.
        a: usize,
        /// Distinct verified relays for `conflict.envelope_b`.
        b: usize,
    },
}

fn standing_with_counts(
    conflict: &Conflict,
    evidence: &ConflictEvidence,
) -> (QuorumStanding, usize, usize) {
    let n_a = count_distinct_valid_relays(
        &evidence.envelope_a_observations,
        conflict.sequence,
        &conflict.envelope_a,
    )
    .len();
    let n_b = count_distinct_valid_relays(
        &evidence.envelope_b_observations,
        conflict.sequence,
        &conflict.envelope_b,
    )
    .len();

    let standing = if n_a >= MIN_QUORUM && n_a > n_b {
        QuorumStanding::Decisive(conflict.envelope_a)
    } else if n_b >= MIN_QUORUM && n_b > n_a {
        QuorumStanding::Decisive(conflict.envelope_b)
    } else if n_a >= MIN_QUORUM && n_b >= MIN_QUORUM {
        // Neither side is strictly greater and both cleared quorum, so the
        // counts are necessarily equal.
        QuorumStanding::QuorumTie {
            distinct_relays_each: n_a,
        }
    } else {
        QuorumStanding::Insufficient { a: n_a, b: n_b }
    };

    (standing, n_a, n_b)
}

/// Weigh `conflict` on relay-quorum evidence alone, without deciding it. This
/// is exactly what [`resolve_conflict`] computes internally before it either
/// returns a winner or an `Err`; callers that need to know *why* a conflict is
/// unresolved (a quorum-met tie, eligible for a VRF tie-break, vs. an
/// under-evidenced one that is not) use this.
pub fn quorum_standing(conflict: &Conflict, evidence: &ConflictEvidence) -> QuorumStanding {
    standing_with_counts(conflict, evidence).0
}

/// The complete off-chain decision order for a two-envelope [`Conflict`], with
/// the VRF tie-break of issue #067 as the explicit last-resort step.
///
/// 1. **Relay quorum + strict majority** ([`resolve_conflict`] /
///    [`quorum_standing`]). If one side wins, that is the answer and the
///    tie-break is never consulted.
/// 2. **VRF tie-break** — applied *only* when step 1 found a
///    [`QuorumStanding::QuorumTie`] (both sides ≥ [`MIN_QUORUM`] distinct
///    relays and exactly equal: the one case where every deterministic
///    criterion came out even) *and* `tiebreak` was supplied. The tie-break is
///    fully verified here — proof valid against the canonical input derived
///    from the conflict, **and** the evaluator confirmed to be the one
///    [`crate::conflict::vrf_tiebreak::select_tiebreak_evaluator`] picks from
///    `candidate_relays`. A quorum-met tie with no (or an invalid) tie-break
///    still returns `Err(UnresolvedConflict)`.
/// 3. Anything else ([`QuorumStanding::Insufficient`]) →
///    `Err(UnresolvedConflict)` → on-chain escalation, with no tie-break.
///
/// `candidate_relays` must be the committed identities
/// ([`RelayVrfIdentity`]) of the relays that corroborated this conflict — in
/// practice, the [`RelayObservation::relay_pubkey`]s that established the tie,
/// resolved against each relay's signed `PeerIdentity` record. It is the
/// evaluator-selection candidate set; passing a different set changes which
/// evaluator is expected and will reject an otherwise-valid `tiebreak`.
///
/// # Errors
///
/// [`SyncEngineError::UnresolvedConflict`] for every unresolved case (including
/// a tie whose supplied `tiebreak` fails verification — the reason is folded
/// into the message, and the conflict escalates exactly as any other
/// unresolved one would).
pub fn resolve_conflict_with_tiebreak(
    conflict: &Conflict,
    evidence: &ConflictEvidence,
    tiebreak: Option<&TiebreakOutcome>,
    candidate_relays: &[RelayVrfIdentity],
) -> Result<[u8; 32], SyncEngineError> {
    match quorum_standing(conflict, evidence) {
        QuorumStanding::Decisive(winner) => Ok(winner),
        QuorumStanding::QuorumTie {
            distinct_relays_each,
        } => match tiebreak {
            Some(outcome) => {
                verify_tiebreak_with_evaluator(conflict, outcome, candidate_relays).map_err(
                    |e| {
                        SyncEngineError::UnresolvedConflict(format!(
                            "conflict on account {} sequence {} is a quorum-met tie \
                             ({distinct_relays_each} distinct relays each), but the supplied VRF \
                             tie-break did not verify: {e}",
                            conflict.source_account, conflict.sequence,
                        ))
                    },
                )?;
                Ok(outcome.winner)
            }
            None => Err(SyncEngineError::UnresolvedConflict(format!(
                "conflict on account {} sequence {} is a quorum-met tie ({distinct_relays_each} \
                 distinct relays each); no VRF tie-break was supplied by the selected evaluator, \
                 so it escalates on-chain",
                conflict.source_account, conflict.sequence,
            ))),
        },
        QuorumStanding::Insufficient { a, b } => Err(SyncEngineError::UnresolvedConflict(format!(
            "conflict on account {} sequence {} could not be resolved off-chain: {a} vs {b} \
             verified distinct relay(s), and a winning side needs at least {MIN_QUORUM}; not a \
             quorum-met tie, so the VRF tie-break does not apply",
            conflict.source_account, conflict.sequence,
        ))),
    }
}

/// Evidence gathered for a single candidate envelope within an
/// [`NWayConflict`] — the N-way counterpart to the per-side fields on
/// [`ConflictEvidence`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateEvidence {
    pub message_id: [u8; 32],
    /// `TransactionEnvelope.timestamp` as originally signed by this
    /// candidate's sender. Recorded for audit/escalation context only — see
    /// [`resolve_conflict`]'s doc comment for why timestamps never decide.
    pub timestamp: u64,
    /// Every relay observation this node has gathered for this candidate.
    pub observations: Vec<RelayObservation>,
}

/// Resolve an [`NWayConflict`] (three or more envelopes competing for one
/// (account, sequence) slot) to at most one winner, using the same
/// Sybil-resistant relay-quorum rules as [`resolve_conflict`]:
///
/// 1. Each candidate's observations are validated and deduplicated by relay
///    pubkey via [`count_distinct_valid_relays`], exactly as for a pairwise
///    conflict.
/// 2. The candidate with the strict-maximum distinct-relay count across the
///    *entire* candidate set wins, provided that count is at least
///    [`MIN_QUORUM`].
/// 3. If no candidate reaches quorum, or if two or more candidates tie for
///    the top count, the whole slot is unresolved.
///
/// Because the ranking is computed once over every candidate rather than via
/// independent pairwise comparisons, the result can never be intransitive.
/// When `conflict` has exactly two candidates, this reduces to the same
/// decision [`resolve_conflict`] would make from equivalent evidence.
///
/// `evidence` must contain exactly one [`CandidateEvidence`] per envelope in
/// `conflict.message_ids`; mismatched input is a caller bug and is reported
/// as an unresolved conflict rather than panicking, since it can originate
/// from untrusted or racing mesh state.
pub fn resolve_nway_conflict(
    conflict: &NWayConflict,
    evidence: &[CandidateEvidence],
) -> Result<[u8; 32], SyncEngineError> {
    let mut expected_ids = conflict.message_ids.clone();
    expected_ids.sort();
    let mut given_ids: Vec<[u8; 32]> = evidence.iter().map(|e| e.message_id).collect();
    given_ids.sort();
    if expected_ids != given_ids {
        return Err(SyncEngineError::UnresolvedConflict(format!(
            "evidence provided for account {} sequence {} does not match the {} conflicting \
             envelope(s) on that slot",
            conflict.source_account,
            conflict.sequence,
            conflict.message_ids.len(),
        )));
    }

    let counts: Vec<([u8; 32], usize)> = evidence
        .iter()
        .map(|candidate| {
            let n = count_distinct_valid_relays(
                &candidate.observations,
                conflict.sequence,
                &candidate.message_id,
            )
            .len();
            (candidate.message_id, n)
        })
        .collect();

    let max_count = counts.iter().map(|(_, n)| *n).max().expect(
        "NWayConflict::message_ids is always non-empty, and given_ids == expected_ids above",
    );
    let mut top = counts.iter().filter(|(_, n)| *n == max_count);
    let winner = top
        .next()
        .expect("max_count was derived from this same iterator, so at least one match exists");
    let unique_winner = top.next().is_none();

    if unique_winner && max_count >= MIN_QUORUM {
        Ok(winner.0)
    } else {
        Err(SyncEngineError::UnresolvedConflict(format!(
            "conflict on account {} sequence {} among {} candidates could not be resolved \
             off-chain: a winning envelope needs at least {} distinct corroborating relays and \
             strictly more than every other candidate",
            conflict.source_account,
            conflict.sequence,
            conflict.message_ids.len(),
            MIN_QUORUM,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::detector::conflicts_between;
    use crate::conflict::detector::QueuedSlot;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn relay_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn observation_for(key: &SigningKey, tx_id: &[u8; 32], sequence: u64) -> RelayObservation {
        let chain_hash = [7u8; 32];
        RelayObservation {
            relay_pubkey: key.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(key, tx_id, &chain_hash, sequence),
        }
    }

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

    fn empty_evidence() -> ConflictEvidence {
        ConflictEvidence {
            envelope_a_timestamp: 1_700_000_000,
            envelope_b_timestamp: 1_700_000_001,
            envelope_a_observations: Vec::new(),
            envelope_b_observations: Vec::new(),
        }
    }

    fn observations_from_n_distinct_relays(
        n: usize,
        tx_id: &[u8; 32],
        sequence: u64,
    ) -> Vec<RelayObservation> {
        (0..n)
            .map(|_| observation_for(&relay_key(), tx_id, sequence))
            .collect()
    }

    #[test]
    fn test_resolve_conflict_is_unresolved_by_default() {
        let conflict = base_conflict();
        let result = resolve_conflict(&conflict, &empty_evidence());
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_resolution_is_deterministic() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                1,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let first = resolve_conflict(&conflict, &evidence);
        let second = resolve_conflict(&conflict, &evidence);
        assert_eq!(first.unwrap(), second.unwrap());
    }

    #[test]
    fn test_stronger_evidence_side_wins() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                1,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_a);
    }

    #[test]
    fn test_single_relay_insufficient_against_multi_relay() {
        let conflict = base_conflict();
        // Side A is backed by a single relay keypair which resubmits the same
        // proof several times, trying to look like more than one witness.
        let single_relay = relay_key();
        let duplicated_proof = observation_for(
            &single_relay,
            &conflict.envelope_a,
            conflict.sequence as u64,
        );
        let evidence = ConflictEvidence {
            envelope_a_observations: vec![
                duplicated_proof.clone(),
                duplicated_proof.clone(),
                duplicated_proof,
            ],
            envelope_b_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(
            winner, conflict.envelope_b,
            "3 distinct relays must beat 1 relay no matter how many times it resubmits"
        );
    }

    #[test]
    fn test_equal_evidence_is_unresolved() {
        let conflict = base_conflict();
        let evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                2,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                2,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        assert!(matches!(
            resolve_conflict(&conflict, &evidence),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_no_evidence_is_unresolved() {
        let conflict = base_conflict();
        assert!(matches!(
            resolve_conflict(&conflict, &empty_evidence()),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_malformed_proof_is_rejected_not_trusted() {
        let conflict = base_conflict();

        // Side A: 3 distinct relays sign for the *wrong* sequence number, so
        // none of them should count as valid evidence for this conflict, even
        // though each proof is a genuine, validly-signed RelayChainProof.
        let wrong_sequence = conflict.sequence as u64 + 1;
        let envelope_a_observations =
            observations_from_n_distinct_relays(3, &conflict.envelope_a, wrong_sequence);

        // Side B: 3 distinct relays sign correctly for this conflict's
        // sequence.
        let envelope_b_observations =
            observations_from_n_distinct_relays(3, &conflict.envelope_b, conflict.sequence as u64);

        let evidence = ConflictEvidence {
            envelope_a_observations,
            envelope_b_observations,
            ..empty_evidence()
        };

        // If the malformed proofs on side A had been trusted, this would be a
        // 3-vs-3 tie (Unresolved). Because they must be excluded, side A's
        // valid count is actually 0, so side B wins outright.
        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_b);
    }

    #[test]
    fn test_wrong_signature_proof_is_rejected() {
        let conflict = base_conflict();
        // A proof correctly signed for a *different* tx_id (e.g. harvested
        // for envelope_b) must not verify against envelope_a's tx_id, so it
        // shouldn't count as evidence for side A even paired with the
        // correct signer pubkey.
        let key = relay_key();
        let mismatched = RelayObservation {
            relay_pubkey: key.verifying_key().to_bytes(),
            proof: RelayChainProof::sign(
                &key,
                &conflict.envelope_b,
                &[7u8; 32],
                conflict.sequence as u64,
            ),
        };

        let evidence = ConflictEvidence {
            envelope_a_observations: vec![
                mismatched,
                observation_for(&relay_key(), &conflict.envelope_a, conflict.sequence as u64),
            ],
            envelope_b_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };

        // Side A only has 1 genuinely valid relay (the mismatched one is
        // excluded), well short of quorum, so side B wins.
        let winner = resolve_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, conflict.envelope_b);
    }

    // ── N-way resolution ────────────────────────────────────────────────────

    fn base_nway_conflict() -> (NWayConflict, [u8; 32], [u8; 32], [u8; 32]) {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let mut message_ids = vec![a, b, c];
        message_ids.sort();
        (
            NWayConflict {
                source_account: "GABC".to_string(),
                sequence: 101,
                message_ids,
            },
            a,
            b,
            c,
        )
    }

    fn candidate(message_id: [u8; 32], relay_count: usize, sequence: i64) -> CandidateEvidence {
        CandidateEvidence {
            message_id,
            timestamp: 1_700_000_000,
            observations: observations_from_n_distinct_relays(
                relay_count,
                &message_id,
                sequence as u64,
            ),
        }
    }

    #[test]
    fn test_three_way_conflict_picks_single_winner_when_scores_differ() {
        let (conflict, a, b, c) = base_nway_conflict();
        let evidence = vec![
            candidate(a, 3, conflict.sequence),
            candidate(b, 5, conflict.sequence),
            candidate(c, 2, conflict.sequence),
        ];
        let winner = resolve_nway_conflict(&conflict, &evidence).unwrap();
        assert_eq!(winner, b);
    }

    #[test]
    fn test_three_way_conflict_with_tied_top_scores_is_unresolved() {
        let (conflict, a, b, c) = base_nway_conflict();
        // a and b are tied for the top distinct-relay count -- neither one is
        // a strict maximum over the whole set, so the slot must be
        // unresolved even though both individually clear MIN_QUORUM.
        let evidence = vec![
            candidate(a, 4, conflict.sequence),
            candidate(b, 4, conflict.sequence),
            candidate(c, 2, conflict.sequence),
        ];
        let result = resolve_nway_conflict(&conflict, &evidence);
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_n_way_resolution_is_never_intransitive() {
        // A resolver that judged conflicts via independent pairwise
        // comparisons could produce a cycle: A beats B, B beats C, but C
        // beats A. That requires a "beats" relation that depends on which
        // specific pair is being judged, e.g. a Condorcet/rock-paper-
        // scissors-style comparator, rather than a fixed per-candidate
        // measure like our distinct-relay count.
        fn naive_pairwise_beats(x: u8, y: u8) -> bool {
            matches!((x % 3, y % 3), (0, 1) | (1, 2) | (2, 0))
        }

        // Confirm the cycle actually exists for this comparator, so the test
        // demonstrates a real bug class rather than a strawman.
        assert!(naive_pairwise_beats(0, 1)); // A beats B
        assert!(naive_pairwise_beats(1, 2)); // B beats C
        assert!(naive_pairwise_beats(2, 0)); // C beats A -- cycle!

        // `resolve_nway_conflict` never asks "does A beat B" in isolation: it
        // computes every candidate's distinct-relay count once and ranks the
        // whole set together, which is a single total order over `usize` and
        // therefore cannot cycle.
        let (conflict, a, b, c) = base_nway_conflict();
        let evidence = vec![
            candidate(a, 3, conflict.sequence),
            candidate(b, 5, conflict.sequence),
            candidate(c, 2, conflict.sequence),
        ];
        let winner = resolve_nway_conflict(&conflict, &evidence).unwrap();
        // b beats both a and c simultaneously in the same pass -- there is
        // one answer, not a set of pairwise judgments that could disagree.
        assert_eq!(winner, b);
    }

    #[test]
    fn test_existing_two_way_behavior_preserved() {
        // The pairwise path (`resolve_conflict` + `ConflictEvidence`) must
        // keep behaving exactly as before after adding the N-way path, and
        // the N-way path must agree with it when given the same underlying
        // evidence recast as a 2-candidate `NWayConflict`.
        let conflict = base_conflict();
        let pairwise_evidence = ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                3,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                1,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        };
        let pairwise_winner = resolve_conflict(&conflict, &pairwise_evidence).unwrap();
        assert_eq!(pairwise_winner, conflict.envelope_a);

        let mut message_ids = vec![conflict.envelope_a, conflict.envelope_b];
        message_ids.sort();
        let nway_conflict = NWayConflict {
            source_account: conflict.source_account.clone(),
            sequence: conflict.sequence,
            message_ids,
        };
        let nway_evidence = vec![
            CandidateEvidence {
                message_id: conflict.envelope_a,
                timestamp: pairwise_evidence.envelope_a_timestamp,
                observations: pairwise_evidence.envelope_a_observations.clone(),
            },
            CandidateEvidence {
                message_id: conflict.envelope_b,
                timestamp: pairwise_evidence.envelope_b_timestamp,
                observations: pairwise_evidence.envelope_b_observations.clone(),
            },
        ];
        let nway_winner = resolve_nway_conflict(&nway_conflict, &nway_evidence).unwrap();
        assert_eq!(nway_winner, pairwise_winner);
    }

    #[test]
    fn test_resolve_nway_conflict_rejects_mismatched_evidence() {
        let (conflict, a, b, _c) = base_nway_conflict();
        // Only two of the three candidates have evidence supplied -- a
        // caller bug.
        let evidence = vec![
            candidate(a, 3, conflict.sequence),
            candidate(b, 5, conflict.sequence),
        ];
        let result = resolve_nway_conflict(&conflict, &evidence);
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_nway_below_quorum_unique_max_is_unresolved() {
        let (conflict, a, b, c) = base_nway_conflict();
        // a is the unique top scorer, but only 1 relay backs it -- short of
        // MIN_QUORUM, so it must not win outright even unopposed at the top.
        let evidence = vec![
            candidate(a, 1, conflict.sequence),
            candidate(b, 0, conflict.sequence),
            candidate(c, 0, conflict.sequence),
        ];
        let result = resolve_nway_conflict(&conflict, &evidence);
        assert!(matches!(
            result,
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    // ── quorum_standing + VRF tie-break integration (issue #067) ────────────

    fn evidence_with_relays(conflict: &Conflict, n_a: usize, n_b: usize) -> ConflictEvidence {
        ConflictEvidence {
            envelope_a_observations: observations_from_n_distinct_relays(
                n_a,
                &conflict.envelope_a,
                conflict.sequence as u64,
            ),
            envelope_b_observations: observations_from_n_distinct_relays(
                n_b,
                &conflict.envelope_b,
                conflict.sequence as u64,
            ),
            ..empty_evidence()
        }
    }

    #[test]
    fn test_quorum_standing_distinguishes_tie_from_insufficient() {
        let conflict = base_conflict();

        assert!(matches!(
            quorum_standing(&conflict, &evidence_with_relays(&conflict, 3, 1)),
            QuorumStanding::Decisive(w) if w == conflict.envelope_a
        ));
        assert!(matches!(
            quorum_standing(&conflict, &evidence_with_relays(&conflict, 3, 3)),
            QuorumStanding::QuorumTie {
                distinct_relays_each: 3
            }
        ));
        // A 1-vs-1 tie is *not* a quorum-met tie: no tie-break, just escalate.
        assert!(matches!(
            quorum_standing(&conflict, &evidence_with_relays(&conflict, 1, 1)),
            QuorumStanding::Insufficient { a: 1, b: 1 }
        ));
        assert!(matches!(
            quorum_standing(&conflict, &evidence_with_relays(&conflict, 0, 0)),
            QuorumStanding::Insufficient { a: 0, b: 0 }
        ));
    }

    #[test]
    fn test_resolve_conflict_behaviour_unchanged_by_refactor() {
        // resolve_conflict must still return exactly what it did before
        // quorum_standing was factored out.
        let conflict = base_conflict();
        assert_eq!(
            resolve_conflict(&conflict, &evidence_with_relays(&conflict, 3, 1)).unwrap(),
            conflict.envelope_a
        );
        assert!(matches!(
            resolve_conflict(&conflict, &evidence_with_relays(&conflict, 2, 2)),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }

    #[test]
    fn test_resolve_conflict_with_tiebreak_decides_a_quorum_met_tie() {
        use crate::conflict::vrf_tiebreak::{
            select_tiebreak_evaluator, vrf_tiebreak, RelayVrfIdentity,
        };

        let conflict = base_conflict();
        let evidence = evidence_with_relays(&conflict, 3, 3);

        // Committed identities of the relays that corroborated the tie.
        let relay_signers: Vec<_> = (0..4).map(|_| relay_key()).collect();
        let candidates: Vec<RelayVrfIdentity> =
            relay_signers.iter().map(RelayVrfIdentity::derive).collect();

        // No tie-break supplied -> still unresolved.
        assert!(matches!(
            resolve_conflict_with_tiebreak(&conflict, &evidence, None, &candidates),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));

        // The selected evaluator produces the tie-break.
        let selected = select_tiebreak_evaluator(&conflict, &candidates)
            .unwrap()
            .identity;
        let selected_key = relay_signers
            .iter()
            .find(|k| k.verifying_key().to_bytes() == selected)
            .unwrap();
        let outcome = vrf_tiebreak(&conflict, selected_key).unwrap();

        let winner =
            resolve_conflict_with_tiebreak(&conflict, &evidence, Some(&outcome), &candidates)
                .unwrap();
        assert_eq!(winner, outcome.winner);
        assert!(winner == conflict.envelope_a || winner == conflict.envelope_b);
    }

    #[test]
    fn test_resolve_conflict_with_tiebreak_ignores_tiebreak_when_not_a_tie() {
        use crate::conflict::vrf_tiebreak::{vrf_tiebreak, RelayVrfIdentity};

        let conflict = base_conflict();
        // Side A wins on quorum outright; a supplied tie-break must not change
        // or override that.
        let evidence = evidence_with_relays(&conflict, 3, 1);
        let rogue = relay_key();
        let outcome = vrf_tiebreak(&conflict, &rogue).unwrap();
        let candidates = [RelayVrfIdentity::derive(&rogue)];

        let winner =
            resolve_conflict_with_tiebreak(&conflict, &evidence, Some(&outcome), &candidates)
                .unwrap();
        assert_eq!(winner, conflict.envelope_a);
    }

    #[test]
    fn test_resolve_conflict_with_tiebreak_rejects_tie_break_from_wrong_evaluator() {
        use crate::conflict::vrf_tiebreak::{
            select_tiebreak_evaluator, vrf_tiebreak, RelayVrfIdentity,
        };

        let conflict = base_conflict();
        let evidence = evidence_with_relays(&conflict, 2, 2);
        let relay_signers: Vec<_> = (0..4).map(|_| relay_key()).collect();
        let candidates: Vec<RelayVrfIdentity> =
            relay_signers.iter().map(RelayVrfIdentity::derive).collect();

        let selected = select_tiebreak_evaluator(&conflict, &candidates)
            .unwrap()
            .identity;
        let wrong_key = relay_signers
            .iter()
            .find(|k| k.verifying_key().to_bytes() != selected)
            .unwrap();
        let outcome = vrf_tiebreak(&conflict, wrong_key).unwrap();

        assert!(matches!(
            resolve_conflict_with_tiebreak(&conflict, &evidence, Some(&outcome), &candidates),
            Err(SyncEngineError::UnresolvedConflict(_))
        ));
    }
}
