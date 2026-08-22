# Verifiable-Delay-Function-Based Fair Dispatch Ordering

Addresses #64.

## Scope note (read this first)

This issue explicitly asks for a design discussion before implementation and flags that "a realistic and honestly-reported negative or partial result is a legitimate, valuable outcome here." In that spirit, this PR ships a **documented reference prototype**, not a production security claim — the mechanism, the four required tests, and real measured costs, alongside an explicit, precise account of what it does and does not guarantee (including the one significant gap that keeps it from being adversarially deployable as-is). See `src/queue/vdf_ordering.rs`'s module doc comment for the full design discussion; this description summarizes it.

## What's here

`src/queue/vdf_ordering.rs` implements a **Wesolowski VDF**: a prover computes `y = x^(2^T) mod N` via `T` sequential modular squarings (no known shortcut without factoring `N`), plus a Fiat-Shamir proof `π` that lets a verifier check the result in `O(log T)` group operations instead of redoing the `T` squarings.

- `VdfParams::generate` — builds a fresh RSA-style modulus + delay parameter.
- `evaluate` / `verify` — produce and check a `VdfProof`, binding the input to an `epoch_seed` (see below).
- `VdfOrderedEntry` / `sort_for_dispatch` — a sibling ordering function for `OutboundTxQueue`'s priority tiers, described below.

## Why Wesolowski, and why not more

Chosen over Pietrzak's construction (similar prover cost, but `O(log T)` proof *rounds* instead of one Fiat-Shamir challenge) and over a class-group instantiation (no trusted setup needed, but implementing class-group arithmetic from scratch is a much larger and riskier surface than this scope). References: Wesolowski, *Efficient Verifiable Delay Functions*, EUROCRYPT 2019; Pietrzak, *Simple Verifiable Delay Functions*, ITCS 2019; Boneh/Bünz/Fisch, *A Survey of Two Verifiable Delay Functions*, 2018.

## The one gap that matters most: trusted setup

Wesolowski's construction over `Z/NZ` is only sound if nobody knows `N`'s factorization — knowing `p, q` lets you compute `φ(N)` and shortcut the whole delay via a single fast modular exponentiation. Real deployments solve this with a class-group construction or an elaborate multi-party ceremony. **`VdfParams::generate` does neither** — it generates `p, q` locally, so whoever calls it knows the factorization. This is fine for local testing/demonstration, explicitly **not sound for an adversarial multi-device deployment**.

I looked for a way to ship a modulus nobody knows the factorization of (e.g. a public RSA Factoring Challenge number) but had no reliable way, in this environment, to transcribe a 617-digit constant with the certainty a security-critical constant deserves — one fetch attempt via a web tool actually corrupted/duplicated the real RSA-2048 number into an ~8,700-character garbage string mid-summarization, which is exactly the failure mode that makes "trust me, I copied it right" unacceptable here. Shipping an unverifiable guess would be worse than shipping nothing, so this prototype ships no production-grade modulus. Closing this gap (via a class-group implementation or a verified trusted-setup modulus) is the single largest remaining piece of work before this scheme is usable between mutually distrusting devices.

## Binding to real time

A VDF alone only proves "at least `T` sequential steps elapsed since `x` was fixed" — nothing about calendar time unless `x` is bound to something the prover couldn't have known in advance. Deriving `x` purely from the envelope's own content would be a critical flaw: a device could precompute a proof for a transaction it hasn't queued yet, at its leisure. `evaluate`/`verify` require an explicit `epoch_seed` — an unpredictable value published by the relay/mesh at the start of a dispatch round (a natural candidate already in this crate: `TransparencyLog`'s root hash at round start). This module implements the binding; it does **not** implement the round/epoch-seed distribution protocol itself, which belongs to the mesh/relay networking layer, not this crate.

## Integration with `OutboundTxQueue`

`OutboundTxQueue` itself is untouched — its `BinaryHeap`/`Ord` machinery and Emergency-guard logic are already covered by an extensive existing test suite, and this feature only matters in the shared-relay/multi-device fairness context. `VdfOrderedEntry` + `sort_for_dispatch` provide a sibling ordering function reusing the identical `TxPriority` tiering: priority still dominates absolutely; VDF evidence is only ever a tie-break *within* a tier (an entry with a currently-valid proof beats one without); with no VDF evidence anywhere, ordering falls back to today's self-reported `enqueued_at` FIFO — i.e. unchanged behavior.

## Guarantees / non-guarantees (verbatim from the module docs)

**Guarantees:**
- A verifier trusting none of the prover's clock/logs/self-reports can check, in `O(log T)`, whether the prover performed at least `T` sequential squarings binding a specific envelope to a specific epoch seed.
- A party who performed fewer than `T` sequential squarings cannot produce a proof a `T`-configured verifier accepts (see the caveat above for how this prototype's own modulus undermines that claim).
- Because `x` is bound to `epoch_seed`, no device can have begun a valid computation before that seed was published.

**Non-guarantees:**
- Not an upper bound — a device can finish early and simply withhold submission.
- Not parallelism-proof against a well-resourced adversary running multiple separate proofs concurrently.
- Not calibrated against ASICs/optimized implementations (this is unoptimized pure-Rust `num-bigint`).
- Not sound against a party using its own self-generated modulus (see "trusted setup" above).
- Says nothing about which envelope a device chooses to compute a proof for, or whether it ever submits one.

## Measured costs

`measure_vdf_squaring_throughput` times 1024-bit modular squarings and reports µs/squaring. Actually measured on the (shared, virtualized) machine used to build this, single-threaded, unoptimized `num-bigint`:

| build     | measured cost per 1024-bit squaring |
|-----------|--------------------------------------|
| `debug`   | ~24–26 µs |
| `release` | ~1.8 µs |

Release optimization alone bought ~14x here — a concrete illustration of why "T sequential steps" is a more defensible delay unit than "T seconds." These numbers are an explicit same-order-of-magnitude proxy, not a mobile-calibrated figure: real mobile SoCs vary enormously, and GMP/assembly-backed bignum libraries (as real VDF deployments use) are known to run well over an order of magnitude faster for this workload. An honest mobile-calibrated delay parameter would require running this on representative target devices, which wasn't possible in this environment.

## Testing

Required tests, all in `src/queue/vdf_ordering.rs`:
- `test_vdf_proof_verifies_for_honest_evaluation`
- `test_backdated_proof_is_rejected` — a party that only performed a fraction of the required sequential work cannot produce a proof that verifies against the full required delay, even though its own smaller-delay proof is valid on its own terms.
- `test_vdf_evaluation_time_matches_configured_delay_parameter` — asserts evaluation time scales with the delay parameter (proportionality, not an absolute bound, to stay robust across hardware — tolerance widened to accommodate this sandbox's scheduling noise).
- `test_ordering_integration_preserves_priority_tier_semantics` — priority tier dominates absolutely regardless of VDF evidence or self-reported timestamps; VDF evidence only tie-breaks within a tier.

Plus supporting tests: Miller-Rabin sanity against known primes/composites, hash-to-prime determinism, and a check that with no VDF evidence anywhere, ordering is unchanged from today's FIFO.

```
cargo fmt --all -- --check         # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo test                          # 181 passed, 0 failed
```

## Commit

1. `feat(queue): add VDF-based dispatch ordering evidence prototype (#64)`
