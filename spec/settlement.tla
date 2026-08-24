---------------------------- MODULE settlement ----------------------------
EXTENDS Integers, TLC

(*
  Settlement state machine specification for StellarConduit.

  States:
  - Queued: Signed and stored, not yet propagated
  - Propagating: Handed to gossip layer
  - Settled: Confirmed on-chain (terminal)
  - Failed: Propagation/submission failed (non-terminal, can retry)
  - Disputed: Conflict detected, awaiting arbitration

  Legal Transitions:
  Queued -> Propagating
  Queued -> Failed
  Propagating -> Settled
  Propagating -> Failed
  Propagating -> Disputed
  Disputed -> Settled
  Disputed -> Failed
  Failed -> Propagating
*)

CONSTANTS
    Queued,
    Propagating,
    Settled,
    Failed,
    Disputed

(* State space *)
States == {Queued, Propagating, Settled, Failed, Disputed}

(* Legal transitions *)
LegalTransitions == [
    Queued -> {Propagating, Failed},
    Propagating -> {Settled, Failed, Disputed},
    Disputed -> {Settled, Failed},
    Failed -> {Propagating},
    Settled -> {}
]

(* Invariant 1: Terminal state immutability *)
TerminalStates == {Settled}
TerminalImmutability ==
    \A s \in TerminalStates:
        \A next \in States:
            next \notin LegalTransitions[s]

(* Invariant 2: No stuck non-terminal states *)
NonTerminalStates == States \ TerminalStates
NoStuckStates ==
    \A s \in NonTerminalStates:
        LegalTransitions[s] /= {}

(* Invariant 3: All reachable states have a legal transition *)
ReachableStates == {
    Queued,
    Propagating,
    Settled,
    Failed,
    Disputed
}

AllReachableHaveTransitions ==
    \A s \in ReachableStates:
        s \in Settled \/ LegalTransitions[s] /= {}

(* Invariant 4: Disputed only reachable from Propagating *)
DisputedReachability ==
    \A s \in States:
        Disputed \in LegalTransitions[s] => s = Propagating

(* Complete invariant set *)
Invariants ==
    /\ TerminalImmutability
    /\ NoStuckStates
    /\ AllReachableHaveTransitions
    /\ DisputedReachability

(* State machine step *)
Next ==
    \E from \in States:
        \E to \in LegalTransitions[from]:
            state' = to

(* Initial state *)
Init == state = Queued

(* Model checking *)
Spec == Init /\ [][Next]_state

===========================================================
