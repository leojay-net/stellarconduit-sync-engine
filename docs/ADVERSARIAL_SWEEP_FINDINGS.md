# Adversarial sweep findings (#070)

## Setup

`#049`'s full discrete-event harness is not yet a separate crate. This work
ships a **stable harness API** in `src/sim/` (seeded RNG, `MockClock`,
append-only `Trace`, pluggable `AdversarialAgent`) and the three required
Byzantine agents on top of it. Real `conflict::detect_*` /
`resolve_conflict` APIs are exercised — not mocked reimplementations.

## Sweep

| Pass | Seeds | Budget | Result |
|------|-------|--------|--------|
| Local (this PR) | 874 (budget hit) / 2000 requested | 90s | 0 failures after the detector-order fix |
| Default unit sweep | 256 | 30s | 0 failures |
| CI (`adversarial-sweep` job) | 512 | 60s | Wired in `.github/workflows/ci.yml` |

Command:

```bash
ADVERSARIAL_SWEEP_SEEDS=5000 ADVERSARIAL_SWEEP_BUDGET_SECS=180 \
  cargo test --test adversarial_sweep -- --nocapture
```

## Bug found and fixed

**Race agent — non-deterministic conflict list order.**

`detect_conflicts` and `detect_nway_conflicts` built their result `Vec` by
iterating a `HashMap`. Output order therefore depended on insertion order
(and, across processes, on `RandomState`). The race agent submits the same
three-way slot set under every arrival permutation and requires a
**byte-identical** conflict list; that assertion failed until both functions
started sorting their results by `(account, sequence, message_ids…)`.

- Fix: `src/conflict/detector.rs` (stable sort before return).
- Regression: `test_race_agent_detect_conflicts_output_is_insertion_order_independent`
  in `tests/sim/adversarial_agents_test.rs`.

This is exactly the class of bug `#049`/`#070` exist to catch: not a missed
double-spend, but a reproducibility break that would make any seeded
simulation harness useless.

## Other agent outcomes (defended)

| Agent | Attack | Outcome |
|-------|--------|---------|
| `ForgedProofAgent` | Tampered signature, post-sign `chain_hash` mutation, cross-wired proof (A's proof on B), single Sybil relay | Forgeries never overturn an honest quorum of 2; resolver either keeps A or stays unresolved |
| `ReplayAgent` | Valid proof replayed on wrong sequence; lone proof after TTL | Wrong-sequence proofs dropped by the sequence filter; lone stale proof cannot meet `MIN_QUORUM` |
| `RaceAgent` | Same-tick split-brain merge of 3 conflicting envelopes | All 3 pairs + 1 N-way conflict always detected; order stable after the fix above |

## Known residual gaps (not silent)

- **`#046` chain-integrity** is still open. Flat `RelayChainProof` has no hop
  list / signer field, so the forged-proof agent stresses signature +
  sequence binding and Sybil quorum floors — not hop reordering/truncation.
  Once `#046` lands, the same agent trait is the place to mount those
  attacks.
- **Observation freshness** is not enforced inside `resolve_conflict` today.
  The replay agent documents that a cryptographically valid but TTL-expired
  proof still *verifies*; it only fails to *win* because of `MIN_QUORUM`.
  A future freshness policy should be asserted here.
