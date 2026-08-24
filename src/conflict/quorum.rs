//! Open-Membership Byzantine Quorum Protocol for Ad Hoc Conflict-Resolution Committees
//!
//! This module provides a voting and aggregation protocol designed to resolve conflicts
//! that are genuinely ambiguous even with perfect causal history and proof verification.
//! It forms an ad-hoc committee from locally available peers and tallies their votes.
//!
//! # Byzantine Fault Tolerance (BFT) Bound
//!
//! The protocol is parameterized by `quorum_size` (the minimum number of responses `M`
//! needed to make any decision) and `supermajority_threshold` (the number of votes
//! `T` a candidate must receive to win).
//!
//! To provide Byzantine Fault Tolerance, we typically set `T > 2/3 * M`.
//! This ensures that if the number of Byzantine nodes `F` in the sampled committee
//! satisfies `3F < M`, they cannot:
//! 1. Force a wrong `Resolved` outcome (because `F < T`).
//! 2. Mask an honest agreement if we assume an honest supermajority is reachable.
//!
//! ## Graceful Degradation
//!
//! If the number of reachable honest participants is too low, or if the network is
//! split and neither side can muster a supermajority, the protocol degrades gracefully.
//! Instead of silently picking a default winner or making an arbitrary choice, it
//! explicitly returns `SplitDecision` or `NoQuorumReached`.
//!
//! # Sybil Resistance and Open Membership Risks
//!
//! In this mesh environment, devices join and leave dynamically, and there is no
//! central membership registry or stake-based identity.
//!
//! **WARNING**: The current ad-hoc committee sampling (e.g., picking nodes from a
//! local routing table) is vulnerable to Sybil attacks. An attacker could flood the
//! local area with many fake devices they control, heavily biasing the sample. If an
//! attacker controls > 2/3 of the sampled committee, they can force a wrong outcome.
//!
//! Addressing strict Sybil resistance without a fixed validator set is a known hard
//! problem and is explicitly punted to a documented follow-up. Potential future
//! mitigations include:
//! - Proof-of-Relay-Participation weighting (historical honesty).
//! - Resource testing or IP-based rate limiting.

use std::collections::HashMap;

/// The clear, distinguishable outcome of a quorum vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumResult {
    /// A single candidate reached the supermajority threshold.
    Resolved([u8; 32]),
    /// The committee failed to gather the minimum required responses.
    NoQuorumReached,
    /// The required number of responses was gathered, but no candidate reached
    /// the supermajority threshold, indicating a genuine split or Byzantine interference.
    SplitDecision,
}

/// Evaluates a quorum vote to resolve an ambiguous conflict.
///
/// `votes`: An array of candidate identifiers (e.g., message IDs) representing
/// the votes collected from the ad hoc committee.
/// `quorum_size`: The minimum total number of votes required before making a decision.
/// `supermajority_threshold`: The number of votes a single candidate must receive to win.
///
/// Note: To guarantee BFT safety properties, callers should ensure that
/// `supermajority_threshold > 2 * quorum_size / 3`.
pub fn resolve_by_quorum(
    votes: &[[u8; 32]],
    quorum_size: usize,
    supermajority_threshold: usize,
) -> QuorumResult {
    if votes.len() < quorum_size {
        return QuorumResult::NoQuorumReached;
    }

    let mut counts: HashMap<[u8; 32], usize> = HashMap::new();
    for vote in votes {
        *counts.entry(*vote).or_insert(0) += 1;
    }

    for (candidate, count) in counts {
        if count >= supermajority_threshold {
            return QuorumResult::Resolved(candidate);
        }
    }

    QuorumResult::SplitDecision
}

#[cfg(test)]
mod tests {
    use super::*;

    const CANDIDATE_A: [u8; 32] = [1u8; 32];
    const CANDIDATE_B: [u8; 32] = [2u8; 32];
    const CANDIDATE_C: [u8; 32] = [3u8; 32];

    #[test]
    fn test_quorum_reaches_resolution_with_sufficient_honest_participants() {
        // Quorum size 10, supermajority > 6
        let votes = vec![
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_C,
        ]; // 7 votes for A, 2 for B, 1 for C

        let result = resolve_by_quorum(&votes, 10, 7);
        assert_eq!(result, QuorumResult::Resolved(CANDIDATE_A));
    }

    #[test]
    fn test_quorum_reports_no_quorum_when_insufficient_participants_reachable() {
        // We need 10 votes, but only got 9.
        let votes = vec![
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
        ]; // 9 votes for A

        let result = resolve_by_quorum(&votes, 10, 7);
        assert_eq!(result, QuorumResult::NoQuorumReached);
    }

    #[test]
    fn test_byzantine_minority_cannot_force_wrong_outcome() {
        // 10 total participants. 7 honest vote for A, 3 Byzantine vote for B.
        // Byzantine nodes (3) < Threshold (7), so they cannot force B to win.
        let votes = vec![
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A, // 7 Honest
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_B, // 3 Byzantine
        ];

        let result = resolve_by_quorum(&votes, 10, 7);
        assert_eq!(result, QuorumResult::Resolved(CANDIDATE_A));
    }

    #[test]
    fn test_byzantine_majority_beyond_bound_is_detected_as_split_decision_not_silently_trusted() {
        // 10 total participants. We need 7 for supermajority.
        // 4 honest vote for A, 6 Byzantine vote for B.
        // Byzantine nodes (6) > 1/3 bound, so they disrupt the honest consensus.
        // However, 6 < 7 (supermajority threshold), so they CANNOT force a wrong outcome.
        // The protocol fails safely by returning SplitDecision.
        let votes = vec![
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A,
            CANDIDATE_A, // 4 Honest
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_B,
            CANDIDATE_B, // 6 Byzantine
        ];

        let result = resolve_by_quorum(&votes, 10, 7);
        assert_eq!(result, QuorumResult::SplitDecision);
    }
}
