//! VRF-based deterministic tie-break for [`Conflict`] resolution (issue #067).
//!
//! # Where this fits in issue #001's resolution flow
//!
//! [`crate::conflict::resolver::resolve_conflict`] decides a two-envelope
//! conflict by counting **distinct corroborating relays** per side and
//! requiring a quorum plus a strict majority. Its ordering is:
//!
//! 1. discard relay observations that don't verify or don't match the slot;
//! 2. deduplicate the survivors by relay pubkey;
//! 3. a side wins iff it has ≥ `MIN_QUORUM` distinct relays *and* strictly
//!    more than the other side;
//! 4. otherwise the conflict is unresolved off-chain.
//!
//! Step 4 lumps together two very different situations: a conflict *nobody
//! corroborated well enough* (escalate — there is nothing to decide on), and a
//! conflict where **both sides are equally and independently well-corroborated**
//! (a genuine tie: every deterministic criterion the resolver has — relay
//! quorum, and, before it, envelope timestamps and causal history — came out
//! exactly even). This module handles *only* that second case, as the explicit
//! **last-resort step 3.5**, immediately before falling through to on-chain
//! escalation. [`crate::conflict::resolver::resolve_conflict_with_tiebreak`]
//! wires it in; [`crate::conflict::resolver::QuorumStanding`] is the seam that
//! tells the two step-4 situations apart.
//!
//! # Why a VRF and not a lexicographic tie-break
//!
//! `message_id_a < message_id_b` is deterministic and needs no evaluator, but
//! it is **predictable before the envelopes exist**. A party that knows it can
//! win every future tie by making its `message_id` sort first has an incentive
//! to grind toward that (to whatever extent any input to the id is under its
//! influence). A Verifiable Random Function keeps determinism and public
//! verifiability but makes the outcome **unpredictable until both envelopes are
//! fixed**: it is a pseudo-random function of the two `message_id`s under the
//! evaluator's secret key, and neither the evaluator's key nor the other
//! party's `message_id` is known to a party while it is still choosing its own
//! envelope's contents.
//!
//! # Construction
//!
//! `schnorrkel`'s VRF (the one behind Substrate/Polkadot BABE block
//! production — see `Cargo.toml` for the full justification). The evaluator's
//! VRF keypair is derived deterministically from its ed25519 identity seed via
//! `MiniSecretKey::expand(ExpansionMode::Ed25519)`, so a relay identity maps to
//! exactly one VRF key (see [`RelayVrfIdentity::derive`]).
//!
//! * **Canonical input** `alpha = SHA-512(DOMAIN ‖ len(account) ‖ account ‖
//!   sequence_be ‖ min(id_a,id_b) ‖ max(id_a,id_b))` — a pure function of the
//!   [`Conflict`]. Sorting the two ids makes it independent of which side the
//!   detector happened to label `a`. Each `message_id` is the hash of a
//!   fully-signed envelope, so it is fixed at signing time and cannot be
//!   altered after the fact without producing a different envelope (and a
//!   different, unpredictable `alpha`).
//! * **Output selection**: `beta = VRF_output(alpha)`; the winner is
//!   `min(id_a,id_b)` when `beta[0]` is even, else `max(id_a,id_b)`. `beta` is
//!   a PRF output, so this is an unbiased coin.
//! * **Proof**: `schnorrkel`'s 64-byte short DLEQ proof. Anyone holding the
//!   evaluator's VRF public key, the canonical input, and the proof can verify
//!   the output without trusting the evaluator — see [`verify_tiebreak`].
//!   (Only the proof's zero-knowledge blinding is randomised; `beta`, and
//!   therefore `winner`, is fully deterministic.)
//!
//! # Who evaluates the VRF
//!
//! A VRF output is only unbiasable if the *key* is fixed before the input is
//! known. So the evaluator cannot be free-chosen after a conflict appears, and
//! it must not be either conflicting party. [`select_tiebreak_evaluator`]
//! derives it deterministically: from the set of relay identities that
//! corroborated the conflict (the same relays whose proofs established the tie
//! in step 2 above — already carried in
//! [`crate::conflict::resolver::ConflictEvidence`], and published with a VRF
//! key in each relay's signed `PeerIdentity` gossip long before this conflict),
//! pick `argmin_r SHA-512(EVALUATOR_DOMAIN ‖ alpha ‖ r.identity)`.
//!
//! * Neither conflicting party is in that set — the parties are envelope
//!   *originators*, the candidates are the mesh *relays* that forwarded them.
//! * Even a party that also operates one of those relays cannot steer the
//!   choice onto its own relay: the selection key is `SHA-512(… ‖ alpha ‖ …)`
//!   and `alpha` is pinned by both committed `message_id`s. Moving the choice
//!   would mean grinding its own envelope hash — `n`-way work for `n`
//!   candidates — *and* every such attempt also re-randomises `beta`, so there
//!   is no "pick a `message_id` that makes me the evaluator *and* wins" path.
//! * If the selected evaluator is offline, the conflict simply stays
//!   unresolved and escalates on-chain. There is deliberately no "next relay"
//!   fallback, since that would re-introduce a choice.

use ed25519_dalek::SigningKey;
use schnorrkel::vrf::{VRFPreOut, VRFProof};
use schnorrkel::{signing_context, ExpansionMode, MiniSecretKey, PublicKey};
use sha2::{Digest, Sha512};

use crate::conflict::detector::Conflict;
use crate::errors::SyncEngineError;

/// Domain separator folded into the canonical VRF input `alpha`.
const INPUT_DOMAIN: &[u8] = b"stellarconduit/conflict/vrf-tiebreak/v1/input";
/// Domain separator for the deterministic evaluator-selection hash.
const EVALUATOR_DOMAIN: &[u8] = b"stellarconduit/conflict/vrf-tiebreak/v1/evaluator";
/// `schnorrkel` signing-context label for the VRF transcript.
const VRF_CONTEXT: &[u8] = b"stellarconduit/conflict/vrf-tiebreak/v1/vrf";
/// `make_bytes` label for turning the VRF in/out into the selection coin.
const OUTPUT_LABEL: &[u8] = b"stellarconduit/conflict/vrf-tiebreak/v1/winner";

/// A relay's committed identity for tie-break purposes: the ed25519 identity
/// key it signs `RelayChainProof`s and its `PeerIdentity` record with, plus
/// the `schnorrkel` VRF public key it published in that same record.
///
/// Both halves are fixed in signed `PeerIdentity` gossip
/// (`stellarconduit_core::peer::identity`) well before any specific conflict,
/// which is exactly what stops a selected evaluator from grinding a favourable
/// VRF key after seeing a conflict's inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayVrfIdentity {
    /// ed25519 identity public key (matches `RelayObservation::relay_pubkey`).
    pub identity: [u8; 32],
    /// `schnorrkel` VRF public key, 32 bytes.
    pub vrf_public: [u8; 32],
}

impl RelayVrfIdentity {
    /// The canonical VRF identity for an ed25519 signing key: the VRF keypair
    /// obtained by `MiniSecretKey(seed).expand(Ed25519)`.
    ///
    /// A well-behaved relay derives its VRF key this way once, from its
    /// identity seed, so there is exactly one VRF key per identity and nothing
    /// extra to protect or rotate.
    pub fn derive(signing_key: &SigningKey) -> Self {
        let keypair = expand_vrf_keypair(signing_key);
        Self {
            identity: signing_key.verifying_key().to_bytes(),
            vrf_public: keypair.public.to_bytes(),
        }
    }
}

/// A fully self-describing, independently verifiable tie-break decision.
///
/// Everything needed to check the decision without trusting the evaluator is
/// in here: recompute `canonical_input` from the [`Conflict`], verify
/// `vrf_proof` against `evaluator_vrf_public`, recompute `vrf_output`, and
/// re-derive `winner`. [`verify_tiebreak`] does exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TiebreakOutcome {
    /// `message_id` of the winning envelope — always one of
    /// `conflict.envelope_a` / `conflict.envelope_b`.
    pub winner: [u8; 32],
    /// The evaluator's ed25519 identity key — the key [`select_tiebreak_evaluator`]
    /// pins down and that the relay's `RelayChainProof`s are signed with.
    pub evaluator_identity: [u8; 32],
    /// The evaluator's `schnorrkel` VRF public key. Carried so a third party
    /// can verify `vrf_proof`; bound to `evaluator_identity` because a relay
    /// publishes it in the same signed `PeerIdentity` record (and derives it
    /// deterministically from the identity seed — see [`RelayVrfIdentity`]).
    pub evaluator_vrf_public: [u8; 32],
    /// The canonical VRF input `alpha`, echoed for auditability. A pure
    /// function of the [`Conflict`]; [`verify_tiebreak`] recomputes and
    /// cross-checks it.
    pub canonical_input: [u8; 64],
    /// VRF pre-output (`gamma`), 32 bytes.
    pub vrf_preout: [u8; 32],
    /// `schnorrkel` short VRF proof (`pi`), 64 bytes. Only the evaluator can
    /// produce it; anyone can verify it.
    pub vrf_proof: [u8; 64],
    /// The 32-byte VRF output `beta` from which `winner` is derived, included
    /// so verification is a pure recomputation.
    pub vrf_output: [u8; 32],
}

/// Sorted `(min, max)` of the conflict's two envelope ids.
fn ordered_pair(conflict: &Conflict) -> ([u8; 32], [u8; 32]) {
    if conflict.envelope_a <= conflict.envelope_b {
        (conflict.envelope_a, conflict.envelope_b)
    } else {
        (conflict.envelope_b, conflict.envelope_a)
    }
}

/// `alpha` — the canonical, order-independent, unpredictable-in-advance VRF
/// input for `conflict`.
fn canonical_input(conflict: &Conflict) -> [u8; 64] {
    let (lo, hi) = ordered_pair(conflict);
    let mut h = Sha512::new();
    h.update(INPUT_DOMAIN);
    h.update((conflict.source_account.len() as u64).to_be_bytes());
    h.update(conflict.source_account.as_bytes());
    h.update(conflict.sequence.to_be_bytes());
    h.update(lo);
    h.update(hi);
    h.finalize().into()
}

/// Derive the evaluator's VRF keypair from its ed25519 signing seed.
fn expand_vrf_keypair(signing_key: &SigningKey) -> schnorrkel::Keypair {
    // `SigningKey::to_bytes` is the 32-byte seed; `MiniSecretKey::from_bytes`
    // only rejects a wrong length, which cannot happen here.
    MiniSecretKey::from_bytes(&signing_key.to_bytes())
        .expect("ed25519 SigningKey seed is always 32 bytes")
        .expand_to_keypair(ExpansionMode::Ed25519)
}

/// Map a 32-byte `beta` to the winning id: even first byte → `min`, odd → `max`.
fn winner_from_output(conflict: &Conflict, beta: &[u8; 32]) -> [u8; 32] {
    let (lo, hi) = ordered_pair(conflict);
    if beta[0] & 1 == 0 {
        lo
    } else {
        hi
    }
}

/// Evaluate the VRF tie-break for `conflict` under `evaluator_key`.
///
/// This is the last-resort step of issue #001's resolution flow, invoked only
/// on a genuine quorum-met tie (see the module docs). It does **not** itself
/// check that `evaluator_key` is the legitimately selected evaluator — that is
/// [`select_tiebreak_evaluator`]'s job, enforced at verification time by
/// [`verify_tiebreak_with_evaluator`] and in the flow by
/// [`crate::conflict::resolver::resolve_conflict_with_tiebreak`]. A node calls
/// this only once it has determined (via [`select_tiebreak_evaluator`]) that it
/// *is* that evaluator.
///
/// # Errors
///
/// [`SyncEngineError::VrfTiebreak`] never actually arises here today (the only
/// fallible step, key expansion, cannot fail for a real `SigningKey`); the
/// `Result` is kept for forward compatibility and signature symmetry with
/// [`verify_tiebreak`].
pub fn vrf_tiebreak(
    conflict: &Conflict,
    evaluator_key: &SigningKey,
) -> Result<TiebreakOutcome, SyncEngineError> {
    let keypair = expand_vrf_keypair(evaluator_key);
    let alpha = canonical_input(conflict);

    let transcript = signing_context(VRF_CONTEXT).bytes(&alpha);
    let (in_out, proof, _batchable) = keypair.vrf_sign(transcript);

    let beta: [u8; 32] = in_out.make_bytes(OUTPUT_LABEL);
    let winner = winner_from_output(conflict, &beta);

    Ok(TiebreakOutcome {
        winner,
        evaluator_identity: evaluator_key.verifying_key().to_bytes(),
        evaluator_vrf_public: keypair.public.to_bytes(),
        canonical_input: alpha,
        vrf_preout: in_out.to_preout().to_bytes(),
        vrf_proof: proof.to_bytes(),
        vrf_output: beta,
    })
}

/// Independently verify a [`TiebreakOutcome`] against `conflict`, using only
/// public inputs (no secret key, no trust in the evaluator).
///
/// Checks, in order:
/// 1. `outcome.canonical_input` matches `alpha` recomputed from `conflict`;
/// 2. `outcome.winner` is actually one of the conflict's two envelopes;
/// 3. the `schnorrkel` VRF proof verifies against `outcome.evaluator_vrf_public`
///    and the canonical transcript;
/// 4. `outcome.vrf_output` matches `beta` recomputed from the verified proof;
/// 5. `outcome.winner` matches the id re-derived from `beta`.
///
/// This does **not** check *who* the evaluator is — see
/// [`verify_tiebreak_with_evaluator`] for that.
///
/// # Errors
///
/// [`SyncEngineError::VrfTiebreak`] with a description of the first check that
/// failed.
pub fn verify_tiebreak(
    conflict: &Conflict,
    outcome: &TiebreakOutcome,
) -> Result<(), SyncEngineError> {
    let alpha = canonical_input(conflict);
    if outcome.canonical_input != alpha {
        return Err(SyncEngineError::VrfTiebreak(
            "canonical input does not match the conflict".to_string(),
        ));
    }

    let (lo, hi) = ordered_pair(conflict);
    if outcome.winner != lo && outcome.winner != hi {
        return Err(SyncEngineError::VrfTiebreak(
            "winner is not one of the conflicting envelopes".to_string(),
        ));
    }

    let public = PublicKey::from_bytes(&outcome.evaluator_vrf_public)
        .map_err(|e| SyncEngineError::VrfTiebreak(format!("invalid evaluator VRF key: {e}")))?;
    let preout = VRFPreOut::from_bytes(&outcome.vrf_preout)
        .map_err(|e| SyncEngineError::VrfTiebreak(format!("invalid VRF pre-output: {e}")))?;
    let proof = VRFProof::from_bytes(&outcome.vrf_proof)
        .map_err(|e| SyncEngineError::VrfTiebreak(format!("invalid VRF proof encoding: {e}")))?;

    let transcript = signing_context(VRF_CONTEXT).bytes(&alpha);
    let (in_out, _batchable) = public
        .vrf_verify(transcript, &preout, &proof)
        .map_err(|e| SyncEngineError::VrfTiebreak(format!("VRF proof failed verification: {e}")))?;

    let beta: [u8; 32] = in_out.make_bytes(OUTPUT_LABEL);
    if beta != outcome.vrf_output {
        return Err(SyncEngineError::VrfTiebreak(
            "recomputed VRF output does not match the outcome".to_string(),
        ));
    }

    if winner_from_output(conflict, &beta) != outcome.winner {
        return Err(SyncEngineError::VrfTiebreak(
            "winner is not consistent with the VRF output".to_string(),
        ));
    }

    Ok(())
}

/// Deterministically select the relay that must evaluate the tie-break for
/// `conflict` from `candidates` (the relay identities that corroborated it).
///
/// Returns `argmin_r SHA-512(EVALUATOR_DOMAIN ‖ alpha ‖ r.identity)`, with ties
/// on the digest (cryptographically negligible) broken by `identity` bytes so
/// the function is total. `None` iff `candidates` is empty.
///
/// The result is a pure function of `conflict` and the candidate set, so every
/// node with the same view computes the same evaluator. See the module docs for
/// why this cannot be steered by either conflicting party.
pub fn select_tiebreak_evaluator<'a>(
    conflict: &Conflict,
    candidates: &'a [RelayVrfIdentity],
) -> Option<&'a RelayVrfIdentity> {
    let alpha = canonical_input(conflict);
    candidates.iter().min_by_key(|candidate| {
        let mut h = Sha512::new();
        h.update(EVALUATOR_DOMAIN);
        h.update(alpha);
        h.update(candidate.identity);
        let digest: [u8; 64] = h.finalize().into();
        (digest, candidate.identity)
    })
}

/// [`verify_tiebreak`] plus a check that `outcome`'s evaluator is exactly the
/// one [`select_tiebreak_evaluator`] picks from `candidates`.
///
/// This is the full check the resolution flow needs: a valid VRF proof from
/// the *wrong* evaluator (e.g. a conflicting party who also runs a relay, or
/// any relay that isn't the selected one) is rejected here.
///
/// # Errors
///
/// [`SyncEngineError::VrfTiebreak`] if [`verify_tiebreak`] fails, if
/// `candidates` is empty, or if the selected evaluator's identity / VRF key
/// does not match `outcome`.
pub fn verify_tiebreak_with_evaluator(
    conflict: &Conflict,
    outcome: &TiebreakOutcome,
    candidates: &[RelayVrfIdentity],
) -> Result<(), SyncEngineError> {
    verify_tiebreak(conflict, outcome)?;

    let selected = select_tiebreak_evaluator(conflict, candidates).ok_or_else(|| {
        SyncEngineError::VrfTiebreak(
            "no candidate relays available to select a tie-break evaluator".to_string(),
        )
    })?;

    if selected.identity != outcome.evaluator_identity {
        return Err(SyncEngineError::VrfTiebreak(format!(
            "tie-break was evaluated by {}, but the selected evaluator is {}",
            hex::encode(outcome.evaluator_identity),
            hex::encode(selected.identity),
        )));
    }
    if selected.vrf_public != outcome.evaluator_vrf_public {
        return Err(SyncEngineError::VrfTiebreak(
            "outcome's VRF key does not match the selected evaluator's committed VRF key"
                .to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conflict::detector::{conflicts_between, QueuedSlot};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn conflict_from(id_a: u8, id_b: u8) -> Conflict {
        let a = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [id_a; 32],
        };
        let b = QueuedSlot {
            source_account: "GABC".to_string(),
            sequence: 101,
            message_id: [id_b; 32],
        };
        conflicts_between(&a, &b).unwrap()
    }

    fn base_conflict() -> Conflict {
        conflict_from(1, 2)
    }

    fn relay_set(n: usize) -> (Vec<SigningKey>, Vec<RelayVrfIdentity>) {
        let keys: Vec<SigningKey> = (0..n).map(|_| key()).collect();
        let ids = keys.iter().map(RelayVrfIdentity::derive).collect();
        (keys, ids)
    }

    // ── Required: test_vrf_tiebreak_is_deterministic_for_fixed_inputs ────────

    #[test]
    fn test_vrf_tiebreak_is_deterministic_for_fixed_inputs() {
        let conflict = base_conflict();
        let evaluator = key();

        let first = vrf_tiebreak(&conflict, &evaluator).unwrap();
        let second = vrf_tiebreak(&conflict, &evaluator).unwrap();

        // The proof carries fresh zero-knowledge blinding each call, but the
        // decision-bearing fields are a pure function of the inputs.
        assert_eq!(first.winner, second.winner);
        assert_eq!(first.vrf_output, second.vrf_output);
        assert_eq!(first.vrf_preout, second.vrf_preout);
        assert_eq!(first.canonical_input, second.canonical_input);

        // Both proofs still verify despite differing byte-for-byte.
        verify_tiebreak(&conflict, &first).unwrap();
        verify_tiebreak(&conflict, &second).unwrap();
    }

    #[test]
    fn test_canonical_input_is_label_order_independent() {
        // The detector labelling a vs b must not change the outcome.
        let forward = conflict_from(1, 2);
        let reversed = Conflict {
            envelope_a: forward.envelope_b,
            envelope_b: forward.envelope_a,
            ..forward.clone()
        };
        let evaluator = key();
        let a = vrf_tiebreak(&forward, &evaluator).unwrap();
        let b = vrf_tiebreak(&reversed, &evaluator).unwrap();
        assert_eq!(a.canonical_input, b.canonical_input);
        assert_eq!(a.winner, b.winner);
    }

    // ── Required: test_vrf_tiebreak_output_verifies_independently ────────────

    #[test]
    fn test_vrf_tiebreak_output_verifies_independently() {
        let conflict = base_conflict();
        let evaluator = key();
        let outcome = vrf_tiebreak(&conflict, &evaluator).unwrap();

        // A third party with only the conflict and the outcome (no secret key)
        // can confirm the decision.
        verify_tiebreak(&conflict, &outcome).unwrap();

        // And it is a real decision: the winner is one of the two envelopes.
        assert!(outcome.winner == conflict.envelope_a || outcome.winner == conflict.envelope_b);
    }

    // ── Required: test_tampered_proof_fails_verification ────────────────────

    #[test]
    fn test_tampered_proof_fails_verification() {
        let conflict = base_conflict();
        let evaluator = key();
        let good = vrf_tiebreak(&conflict, &evaluator).unwrap();

        // Flip one bit of the proof.
        let mut tampered = good.clone();
        tampered.vrf_proof[0] ^= 0x01;
        assert!(verify_tiebreak(&conflict, &tampered).is_err());

        // Tamper with the claimed winner instead.
        let mut flipped_winner = good.clone();
        flipped_winner.winner = if good.winner == conflict.envelope_a {
            conflict.envelope_b
        } else {
            conflict.envelope_a
        };
        assert!(verify_tiebreak(&conflict, &flipped_winner).is_err());

        // Tamper with the VRF output.
        let mut flipped_output = good.clone();
        flipped_output.vrf_output[0] ^= 0xff;
        assert!(verify_tiebreak(&conflict, &flipped_output).is_err());

        // Swap in a different evaluator's VRF key.
        let mut wrong_key = good.clone();
        wrong_key.evaluator_vrf_public = RelayVrfIdentity::derive(&key()).vrf_public;
        assert!(verify_tiebreak(&conflict, &wrong_key).is_err());

        // Verify against the wrong conflict.
        assert!(verify_tiebreak(&conflict_from(3, 4), &good).is_err());
    }

    // ── Required: test_evaluator_selection_is_not_self_chosen_by_either ─────
    //             _conflicting_party

    #[test]
    fn test_evaluator_selection_is_not_self_chosen_by_either_conflicting_party() {
        let conflict = base_conflict();

        // The two conflicting parties. They are envelope originators, not
        // relays, so their identities are simply not in the candidate set.
        let party_a = key();
        let party_b = key();

        let (relay_keys, mut candidates) = relay_set(5);
        let selected = select_tiebreak_evaluator(&conflict, &candidates).unwrap();

        assert_ne!(selected.identity, party_a.verifying_key().to_bytes());
        assert_ne!(selected.identity, party_b.verifying_key().to_bytes());
        assert!(relay_keys
            .iter()
            .any(|k| k.verifying_key().to_bytes() == selected.identity));

        // Selection is a pure function of the committed inputs.
        assert_eq!(
            select_tiebreak_evaluator(&conflict, &candidates)
                .unwrap()
                .identity,
            selected.identity,
        );

        // Now the adversarial case: party A *also* runs a relay that is in the
        // candidate set. It still cannot steer the selection onto its own
        // relay by choosing its envelope's contents, because the selection
        // hash is over `alpha`, which is pinned by both message_ids. Sweeping
        // many possible `message_id`s for A's envelope, A's own relay is
        // selected no more often than any other candidate (≈ 1/n) — i.e. A has
        // no better-than-random control.
        let party_a_relay = RelayVrfIdentity::derive(&party_a);
        candidates.push(party_a_relay);
        let n = candidates.len();

        let trials = 4_000u64;
        let mut a_relay_selected = 0u64;
        for i in 0..trials {
            // Each distinct envelope A might craft yields a different (and, via
            // the envelope hash, unpredictable) message_id — modelled here as
            // SHA-512(i) truncated, standing in for the hash of a crafted
            // envelope.
            let mut crafted_id = [0u8; 32];
            crafted_id.copy_from_slice(&Sha512::digest(i.to_be_bytes())[..32]);
            let crafted = conflict_from_ids(crafted_id, conflict.envelope_b);
            let winner = select_tiebreak_evaluator(&crafted, &candidates).unwrap();
            if winner.identity == party_a_relay.identity {
                a_relay_selected += 1;
            }
        }
        let expected = trials as f64 / n as f64;
        // Selection is genuinely uniform over the candidate set, so A's own
        // relay wins ≈ 1/n of the time no matter how A crafts its id. The band
        // is wide enough never to flake but tight enough to catch gross
        // steering (a real bias would push this toward `trials`).
        assert!(
            (a_relay_selected as f64) < expected * 1.35,
            "party A's own relay was selected {a_relay_selected}/{trials} times \
             (expected ≈ {expected:.0}); selection appears steerable"
        );
    }

    fn conflict_from_ids(a: [u8; 32], b: [u8; 32]) -> Conflict {
        Conflict {
            source_account: "GABC".to_string(),
            sequence: 101,
            envelope_a: a,
            envelope_b: b,
        }
    }

    // ── Acceptance criterion 2: resistance to post-hoc envelope choice ─────

    #[test]
    fn test_tiebreak_is_unbiased_against_a_party_choosing_content_after_seeing_the_other() {
        // Threat model: party B has already seen party A's envelope (fixed
        // `envelope_a`) and now gets to choose its own envelope's contents,
        // hoping to win the eventual tie-break. B does *not* hold the selected
        // evaluator's secret key, so for each candidate envelope it might
        // craft, the outcome is a fresh VRF draw it cannot compute in advance.
        //
        // We model B trying many envelopes and, for each, ask whether B's
        // envelope would win. An honest evaluator's key is fixed up front. B
        // wins ≈ 50% of the time regardless — there is no craftable envelope
        // property that biases the coin.
        let evaluator = key();
        let envelope_a = [0xAAu8; 32];

        let trials = 500u64;
        let mut b_wins = 0u64;
        for i in 0..trials {
            // A hash-like spread of "B's crafted envelope id". In reality this
            // is SHA-512 of B's signed envelope; B cannot predict the draw for
            // any choice without the evaluator's secret key.
            let mut b_id = [0u8; 32];
            b_id.copy_from_slice(&Sha512::digest(i.to_be_bytes())[..32]);
            if b_id == envelope_a {
                continue;
            }
            let conflict = conflict_from_ids(envelope_a, b_id);
            let outcome = vrf_tiebreak(&conflict, &evaluator).unwrap();
            if outcome.winner == b_id {
                b_wins += 1;
            }
        }

        // 500 trials of a fair coin: P(rate outside 0.40..0.60) < 1e-4.
        let rate = b_wins as f64 / trials as f64;
        assert!(
            (0.40..=0.60).contains(&rate),
            "party B won {b_wins}/{trials} = {rate:.3}; expected ≈ 0.5 (no bias from crafting)"
        );
    }

    #[test]
    fn test_verify_tiebreak_with_evaluator_rejects_wrong_evaluator() {
        let conflict = base_conflict();
        let (relay_keys, candidates) = relay_set(4);

        let selected = select_tiebreak_evaluator(&conflict, &candidates)
            .unwrap()
            .identity;
        let selected_key = relay_keys
            .iter()
            .find(|k| k.verifying_key().to_bytes() == selected)
            .unwrap();
        let not_selected_key = relay_keys
            .iter()
            .find(|k| k.verifying_key().to_bytes() != selected)
            .unwrap();

        // Correct evaluator: accepted.
        let good = vrf_tiebreak(&conflict, selected_key).unwrap();
        verify_tiebreak_with_evaluator(&conflict, &good, &candidates).unwrap();

        // A different relay produced a perfectly valid VRF proof, but it is not
        // the selected evaluator: rejected.
        let usurped = vrf_tiebreak(&conflict, not_selected_key).unwrap();
        verify_tiebreak(&conflict, &usurped).unwrap(); // proof itself is fine
        assert!(verify_tiebreak_with_evaluator(&conflict, &usurped, &candidates).is_err());

        // Empty candidate set: rejected.
        assert!(verify_tiebreak_with_evaluator(&conflict, &good, &[]).is_err());
    }

    #[test]
    fn test_derived_vrf_identity_is_stable() {
        let k = key();
        assert_eq!(RelayVrfIdentity::derive(&k), RelayVrfIdentity::derive(&k));
        assert_eq!(
            RelayVrfIdentity::derive(&k).identity,
            k.verifying_key().to_bytes()
        );
    }
}
