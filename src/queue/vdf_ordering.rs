//! Verifiable-Delay-Function-based dispatch ordering evidence — issue #64.
//!
//! # Problem
//!
//! [`crate::queue::OutboundTxQueue`] orders envelopes by [`crate::queue::TxPriority`]
//! and, within a tier, by `enqueued_at` — a timestamp the local device assigns
//! and controls. On a shared relay terminal (or any setting where a device
//! operator benefits from reordering payments — e.g. front-running a
//! merchant payment to a limited-liquidity destination with the operator's
//! own transaction), nothing stops the operator from lying about
//! `enqueued_at`, or delaying processing of others' envelopes while
//! prioritizing their own: the ordering evidence is entirely self-reported
//! and unverifiable by anyone else in the mesh.
//!
//! # Design discussion
//!
//! **Construction: Wesolowski's VDF over an RSA-style modulus.** The prover
//! computes `y = x^(2^T) mod N` via `T` *sequential* modular squarings (no
//! known way to shortcut this without factoring `N`), then a
//! Fiat-Shamir-derived proof `π` lets a verifier check the result in
//! `O(log T)` group operations instead of redoing the `T` squarings. This is
//! chosen over Pietrzak's construction (broadly similar prover cost, but an
//! interactive-turned-non-interactive proof of `O(log T)` *rounds*, each its
//! own exponentiation, versus Wesolowski's single Fiat-Shamir challenge) and
//! over a class-group instantiation (Pietrzak/Wesolowski without a trusted
//! setup — but implementing class-group arithmetic, ideal reduction, and
//! composition from scratch is a much larger and riskier surface than this
//! prototype's scope; noted below as unimplemented future work). References:
//! Wesolowski, *Efficient Verifiable Delay Functions*, EUROCRYPT 2019;
//! Pietrzak, *Simple Verifiable Delay Functions*, ITCS 2019; Boneh, Bünz,
//! Fisch, *A Survey of Two Verifiable Delay Functions*, 2018.
//!
//! **The trusted-setup problem — the single most important caveat in this
//! module.** Wesolowski's construction over `Z/NZ` is only sound if nobody
//! knows `N`'s factorization: knowing `p, q` lets you compute `φ(N)`, reduce
//! the giant exponent `2^T` modulo `φ(N)`, and evaluate the "delay" in a
//! single fast modular exponentiation — i.e. completely bypass the delay.
//! Real deployments solve this with either a class-group construction (no
//! such shortcut exists) or an elaborate multi-party computation ceremony
//! that generates `N` such that *no participant* (and no coalition short of
//! all of them) learns its factorization. **[`VdfParams::generate`] does
//! neither.** It generates `p` and `q` locally and returns `N = p * q`,
//! which means whoever calls it *knows the factorization* — this is fine for
//! local testing and for demonstrating the mechanism, but is explicitly
//! **not sound for an adversarial multi-device deployment**. This
//! prototype's [`evaluate`] deliberately never uses the factorization
//! shortcut even when it would technically be available to the caller who
//! generated `N` — but a dishonest party who generated their own `N` could,
//! which is exactly why self-generated moduli aren't acceptable in
//! production. I looked for a way to ship a verifiably-nobody-knows-the-
//! factorization modulus (e.g. one of the public RSA Factoring Challenge
//! numbers) but had no reliable way, in this environment, to transcribe a
//! 617-digit constant with the certainty a security-critical constant
//! deserves — including one failed attempt where a fetch tool's page
//! summary silently corrupted/duplicated the digits into a ~8,700-character
//! string. Shipping an unverifiable guess would be worse than shipping
//! nothing, so this prototype ships **no** production-grade modulus at all;
//! see "Non-guarantees" below.
//!
//! **Delay parameter and mobile hardware.** `T` (the squaring count) is the
//! only real "difficulty" knob here. This is a pure-Rust, unoptimized
//! `num-bigint` implementation — real VDF deployments (e.g. the Chia Network
//! VDF competition) use GMP/assembly-optimized squaring and see well over an
//! order of magnitude more throughput than a naive big-integer library.
//! Mobile SoCs also vary enormously in single-core throughput and thermal
//! throttling behavior compared to a development machine. This module
//! **measures actual squaring throughput on whatever machine runs the test
//! suite** (`measure_vdf_squaring_throughput`, `--nocapture` to see the
//! numbers) rather than asserting a specific mobile-calibrated delay — see
//! "Measured costs" below for what was actually observed in this
//! environment, and the explicit caveat that it is a same-order-of-magnitude
//! proxy, not a mobile-calibrated guarantee.
//!
//! **Binding the VDF input to real time.** A VDF alone only proves "at least
//! `T` sequential steps elapsed since `x` was fixed" — it says *nothing*
//! about calendar time unless `x` is bound to something the prover could not
//! have known in advance. Deriving `x` purely from the envelope's own
//! content (e.g. its `message_id`) would be a critical flaw: a device fully
//! controls when it creates its own envelope, so it could compute the VDF
//! for a transaction it hasn't queued yet, at its leisure, and attach the
//! finished proof whenever convenient — providing *no* anti-backdating
//! property at all. [`evaluate`]/[`verify`] therefore require an explicit
//! `epoch_seed`: an unpredictable value published by the relay/mesh at the
//! start of a dispatch round (a natural candidate already in this crate:
//! [`crate::settlement::transparency_log::TransparencyLog`]'s root hash at
//! round start). Binding `x` to `epoch_seed` means no device can have begun
//! computing a valid proof before that round's seed existed. **This module
//! implements the binding; it does not implement the round/epoch-seed
//! distribution protocol itself** — that belongs to the mesh/relay
//! networking layer (`stellarconduit-core`), not this queue-ordering crate,
//! and is explicitly out of scope here.
//!
//! **Integration with [`OutboundTxQueue`].** [`OutboundTxQueue`] itself is
//! left completely unmodified — its `BinaryHeap`/`Ord` machinery and
//! Emergency-guard logic are already covered by an extensive existing test
//! suite, and this feature only matters in the shared-relay/multi-device
//! fairness context, not the common single-device case. Instead,
//! [`VdfOrderedEntry`] and [`sort_for_dispatch`] provide a sibling ordering
//! function reusing the identical [`TxPriority`] tiering: priority still
//! dominates absolutely, and VDF evidence is only ever a *tie-break within a
//! tier* — an entry with a currently-valid VDF proof for the active round is
//! preferred over one without, and among entries with the same
//! evidence-status, ordering falls back to today's self-reported
//! `enqueued_at` FIFO (so, with no VDF evidence anywhere, behavior is
//! unchanged from today).
//!
//! # Guarantees
//!
//! - A verifier holding only `(params, epoch_seed, envelope_id, proof)` —
//!   and trusting none of the prover's clock, logs, or self-reports — can
//!   check in `O(log T)` group operations whether the prover performed at
//!   least `T` sequential squarings binding that specific `envelope_id` to
//!   that specific `epoch_seed`.
//! - A party who has performed fewer than `T` sequential squarings cannot
//!   produce a proof that a verifier configured for `T` will accept (see
//!   `test_backdated_proof_is_rejected` and the "known-factorization" caveat
//!   above for the one way this module's own default parameters undermine
//!   that claim).
//! - Because `x` is bound to `epoch_seed`, no device can have begun a valid
//!   computation before that seed was published/known.
//!
//! # Non-guarantees
//!
//! - **Not an upper bound.** A VDF proves a *minimum* elapsed computation,
//!   never a maximum. A device can finish its proof early and simply
//!   withhold submission — this scheme cannot detect or prevent that; it is
//!   a liveness/censorship concern orthogonal to what VDFs address.
//! - **Not parallelism-proof for a well-resourced adversary.** A party with
//!   several independent cores (or a faster big-integer implementation) can
//!   run multiple *separate* proofs concurrently, each still honestly
//!   sequential on its own thread — this scheme provides no defense against
//!   an operator with more/faster hardware computing several proofs for
//!   several different envelopes in parallel, only against fabricating *one*
//!   proof faster than sequential computation allows.
//! - **Not calibrated against ASICs/optimized implementations.** As noted
//!   above, this is an unoptimized reference implementation; its measured
//!   delay is a lower bound on *this implementation's* sequential steps, not
//!   a defended security margin against a adversary with, say, a GMP- or
//!   hardware-optimized evaluator running many times faster per squaring.
//! - **Not sound against a party who generated its own modulus.** As
//!   detailed above, [`VdfParams::generate`] produces a modulus whose
//!   factorization is known to the caller. A dishonest party using its own
//!   self-generated `N` could bypass the delay entirely via `φ(N)`. This
//!   module does not ship a modulus suitable for adversarial multi-device
//!   deployment (no class-group implementation, no verified trusted-setup
//!   modulus) — closing this gap is the single largest remaining piece of
//!   work before this scheme could be trusted between mutually distrusting
//!   devices.
//! - **Says nothing about which envelope a device chooses to compute a
//!   proof for, or whether it ever does.** A device can simply never submit
//!   a proof for an envelope it wants to suppress.
//!
//! # Measured costs
//!
//! `measure_vdf_squaring_throughput` (below) times a batch of modular
//! squarings on a 1024-bit modulus and reports microseconds/squaring via
//! `println!` (`cargo test vdf_ordering -- --nocapture` to see it, or
//! `cargo test --release ... -- --nocapture` for the release number).
//! Actually measured on the (shared, virtualized) machine used to build this
//! module, single-threaded, `num-bigint` with no assembly optimization:
//!
//! | build     | measured cost per 1024-bit squaring |
//! |-----------|--------------------------------------|
//! | `debug`   | ~24–26 µs                             |
//! | `release` | ~1.8 µs                                |
//!
//! i.e. release-mode optimization alone bought roughly a 14x speedup here —
//! itself a concrete illustration of why "T sequential steps" is a much more
//! defensible unit of delay than "T seconds": the same `T` means a very
//! different wall-clock delay depending on build flags alone, before even
//! accounting for hardware. Purely as illustrative extrapolation *on this
//! same machine* (not a mobile calibration): reaching a 5-second delay would
//! take roughly 200,000 squarings in debug or roughly 2.8 million in
//! release.
//!
//! Treat all of this as a same-order-of-magnitude proxy for mobile hardware,
//! not a calibrated mobile number. Real mobile SoCs vary enormously in
//! single-core throughput and thermal-throttling behavior, and GMP/assembly-
//! backed bignum libraries (as used by real VDF deployments like the Chia
//! Network competition) are known to run well over an order of magnitude
//! faster than a naive big-integer library for exactly this workload. This
//! prototype does not attempt to characterize either gap precisely — an
//! honest mobile-calibrated delay parameter would require actually running
//! this (or a hardened equivalent) on representative target devices, which
//! is beyond what could be done in this environment.

use num_bigint::{BigUint, RandBigInt};
use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::queue::TxPriority;

/// Bit length of the Fiat-Shamir challenge prime `ℓ`. 128 bits matches
/// common practice for this construction's soundness parameter.
const CHALLENGE_PRIME_BITS: u64 = 128;

/// Miller-Rabin rounds for every primality test in this module (both
/// candidate-modulus-prime generation and the deterministic hash-to-prime
/// below). 40 rounds bounds the false-positive probability at ≤ 4^-40,
/// negligible for this purpose.
const MILLER_RABIN_ROUNDS: u32 = 40;

/// Small primes used to cheaply reject the overwhelming majority of
/// composite candidates before paying for a full Miller-Rabin round.
const SMALL_PRIME_SIEVE: &[u32] = &[
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97,
];

/// Public parameters for one VDF instance: the modulus and the fixed number
/// of sequential squarings ("delay", `T`) that both prover and verifier
/// agree on.
///
/// See the module-level "trusted-setup problem" discussion: [`generate`]
/// produces a modulus whose factorization is known to the caller, which is
/// fine for local testing but not for an adversarial deployment.
#[derive(Debug, Clone, PartialEq)]
pub struct VdfParams {
    pub modulus: BigUint,
    pub delay: u64,
}

impl VdfParams {
    /// Generate a fresh modulus locally and pair it with `delay`.
    ///
    /// **The caller learns the factorization of the returned modulus** (it
    /// just generated `p` and `q` itself) — see the module docs. This is
    /// appropriate for tests/benchmarks/demonstrations of the mechanism,
    /// not for a deployment where devices must not be able to shortcut their
    /// own delay.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R, prime_bits: u64, delay: u64) -> Self {
        let p = generate_prime(rng, prime_bits);
        let mut q = generate_prime(rng, prime_bits);
        while q == p {
            q = generate_prime(rng, prime_bits);
        }
        VdfParams {
            modulus: &p * &q,
            delay,
        }
    }
}

/// A Wesolowski VDF proof: the claimed output `y = x^(2^T) mod N` and the
/// proof `π` that it took `T` sequential squarings to produce. `T` itself is
/// deliberately *not* part of this struct — see [`verify`]'s doc comment for
/// why trusting a self-reported delay would defeat the whole point.
#[derive(Debug, Clone, PartialEq)]
pub struct VdfProof {
    pub output: BigUint,
    pub pi: BigUint,
}

/// Evaluate the VDF for `envelope_id` under `epoch_seed`: `params.delay`
/// sequential squarings (the actual delay), then a Wesolowski proof.
pub fn evaluate(params: &VdfParams, epoch_seed: &[u8], envelope_id: &[u8]) -> VdfProof {
    let x = derive_input(&params.modulus, epoch_seed, envelope_id);

    // The delay: `params.delay` sequential modular squarings. Nothing here
    // may be replaced by a shortcut without knowing N's factorization.
    let mut y = x.clone();
    for _ in 0..params.delay {
        y = (&y * &y) % &params.modulus;
    }

    let ell = hash_to_prime(&[
        &x.to_bytes_be(),
        &y.to_bytes_be(),
        &params.delay.to_be_bytes(),
    ]);

    // q = floor(2^T / ell). Materializing 2^T directly is fine at this
    // prototype's delay scale (thousands-to-low-millions of steps, i.e. a
    // T-bit integer of at most a few hundred KB); a production system
    // targeting astronomically larger T would instead compute q's bits
    // incrementally alongside the squaring loop above (see Wesolowski /
    // Boneh-Bünz-Fisch for that technique) to avoid ever materializing 2^T.
    let two_pow_t = BigUint::from(1u32) << (params.delay as usize);
    let q = &two_pow_t / &ell;
    let pi = x.modpow(&q, &params.modulus);

    VdfProof { output: y, pi }
}

/// Verify `proof` for `envelope_id` under `epoch_seed`, against the *fixed*
/// `params.delay` — never a delay the prover claims. If a claimed delay were
/// trusted, a device could simply evaluate for a smaller `T` of its choosing
/// and submit a perfectly valid proof of that smaller, self-chosen delay;
/// binding verification to the protocol's own `params.delay` is exactly what
/// makes it impossible to pass off less work as the required amount (see
/// `test_backdated_proof_is_rejected`).
pub fn verify(params: &VdfParams, epoch_seed: &[u8], envelope_id: &[u8], proof: &VdfProof) -> bool {
    let x = derive_input(&params.modulus, epoch_seed, envelope_id);
    let ell = hash_to_prime(&[
        &x.to_bytes_be(),
        &proof.output.to_bytes_be(),
        &params.delay.to_be_bytes(),
    ]);

    // r = 2^T mod ell, computed via fast square-and-multiply modpow (O(log T)
    // multiplications mod the *small* ell) -- this is what makes
    // verification cheap regardless of how large T is, unlike evaluation.
    let r = BigUint::from(2u32).modpow(&BigUint::from(params.delay), &ell);

    let lhs =
        (proof.pi.modpow(&ell, &params.modulus) * x.modpow(&r, &params.modulus)) % &params.modulus;
    lhs == proof.output
}

/// Derive the VDF input `x` from `epoch_seed` and `envelope_id`, reduced
/// into `[0, modulus)`. Binding to `epoch_seed` (an unpredictable value
/// published at round start, not controlled by any single device) is what
/// gives "cannot be produced before T" real-world meaning -- see the module
/// docs' "Binding the VDF input to real time" section.
fn derive_input(modulus: &BigUint, epoch_seed: &[u8], envelope_id: &[u8]) -> BigUint {
    const SHA256_OUTPUT_BYTES: usize = 32;
    let bytes_needed = (modulus.bits() as usize).div_ceil(8) + 16;
    let mut buf = Vec::with_capacity(bytes_needed + SHA256_OUTPUT_BYTES);
    let mut counter: u32 = 0;
    while buf.len() < bytes_needed {
        let mut hasher = Sha256::new();
        hasher.update(b"stellarconduit-vdf-input-v1");
        hasher.update(epoch_seed);
        hasher.update(envelope_id);
        hasher.update(counter.to_be_bytes());
        buf.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    // A small modulo bias from this reduction is immaterial here: `x` only
    // needs to be an unpredictable, seed-bound element of Z_N, not a
    // uniformly-random one.
    BigUint::from_bytes_be(&buf) % modulus
}

/// Deterministically derive a prime of [`CHALLENGE_PRIME_BITS`] bits from
/// `parts` via hash-then-increment. Must be deterministic (no randomness):
/// prover and verifier each derive `ell` independently and must reach
/// exactly the same value.
fn hash_to_prime(parts: &[&[u8]]) -> BigUint {
    let mut counter: u64 = 0;
    loop {
        let mut hasher = Sha256::new();
        hasher.update(b"stellarconduit-vdf-hash-to-prime-v1");
        for part in parts {
            hasher.update(part);
        }
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();

        let bytes_needed = (CHALLENGE_PRIME_BITS as usize).div_ceil(8);
        let mut candidate = BigUint::from_bytes_be(&digest[..bytes_needed.min(digest.len())]);
        // Force the top bit (exact bit length) and bottom bit (odd).
        candidate |= BigUint::from(1u32) << (CHALLENGE_PRIME_BITS as usize - 1);
        candidate |= BigUint::from(1u32);

        if is_probably_prime_deterministic(&candidate) {
            return candidate;
        }
        counter += 1;
    }
}

/// A witness for round `round` against candidate `n`, derived
/// deterministically so every caller (prover and verifier alike) that runs
/// this primality test on the same `n` makes the same accept/reject
/// decision -- required for [`hash_to_prime`]'s prover/verifier agreement,
/// and equally sound for [`generate_prime`] (Miller-Rabin's soundness holds
/// for any base chosen independent of the candidate's factorization,
/// deterministic or not).
fn deterministic_witness(n: &BigUint, round: u64) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(b"stellarconduit-vdf-miller-rabin-witness-v1");
    hasher.update(n.to_bytes_be());
    hasher.update(round.to_be_bytes());
    let digest = hasher.finalize();
    let raw = BigUint::from_bytes_be(&digest);
    // Land in [2, n-2].
    let span = n - BigUint::from(3u32);
    (raw % span) + BigUint::from(2u32)
}

fn is_probably_prime_deterministic(n: &BigUint) -> bool {
    let zero = BigUint::from(0u32);
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);

    if *n < two {
        return false;
    }
    for &p in SMALL_PRIME_SIEVE {
        let p = BigUint::from(p);
        if *n == p {
            return true;
        }
        if n % &p == zero {
            return false;
        }
    }

    // n - 1 = 2^r * d, d odd.
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut r: u32 = 0;
    while (&d % &two) == zero {
        d /= &two;
        r += 1;
    }

    'witness: for round in 0..MILLER_RABIN_ROUNDS as u64 {
        let a = deterministic_witness(n, round);
        let mut x = a.modpow(&d, n);
        if x == one || x == n_minus_1 {
            continue 'witness;
        }
        for _ in 1..r {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                continue 'witness;
            }
        }
        return false;
    }
    true
}

fn generate_prime<R: RngCore + CryptoRng>(rng: &mut R, bits: u64) -> BigUint {
    loop {
        let mut candidate = rng.gen_biguint(bits);
        candidate |= BigUint::from(1u32) << (bits as usize - 1);
        candidate |= BigUint::from(1u32);
        if is_probably_prime_deterministic(&candidate) {
            return candidate;
        }
    }
}

// ── OutboundTxQueue integration ─────────────────────────────────────────
//
// See the module docs' "Integration with OutboundTxQueue" section:
// OutboundTxQueue itself is untouched; this is a sibling ordering function
// for the shared-relay/multi-device fairness context, reusing TxPriority so
// priority tiers remain absolute and VDF evidence is only ever a tie-break
// within a tier.

/// One envelope's dispatch-ordering evidence for [`sort_for_dispatch`]:
/// its priority tier (governs ordering absolutely, as in
/// [`OutboundTxQueue`](crate::queue::OutboundTxQueue)), its self-reported
/// `enqueued_at` (the existing, unverifiable fallback), and optionally a
/// [`VdfProof`] for the active round.
#[derive(Debug, Clone)]
pub struct VdfOrderedEntry {
    pub envelope_id: [u8; 32],
    pub priority: TxPriority,
    pub enqueued_at: u64,
    pub proof: Option<VdfProof>,
}

/// Order `entries` for dispatch: priority tier first (absolute, identical to
/// [`OutboundTxQueue`](crate::queue::OutboundTxQueue)), then entries with a
/// currently-valid VDF proof for `epoch_seed`/`params` before those without,
/// then self-reported `enqueued_at` (oldest first, today's FIFO fallback),
/// then `envelope_id` as a final deterministic tiebreak.
///
/// With no VDF evidence anywhere, this reduces exactly to today's
/// priority-then-FIFO ordering.
pub fn sort_for_dispatch(
    entries: Vec<VdfOrderedEntry>,
    params: &VdfParams,
    epoch_seed: &[u8],
) -> Vec<VdfOrderedEntry> {
    let mut ranked: Vec<(bool, VdfOrderedEntry)> = entries
        .into_iter()
        .map(|entry| {
            let verified = entry
                .proof
                .as_ref()
                .is_some_and(|proof| verify(params, epoch_seed, &entry.envelope_id, proof));
            (verified, entry)
        })
        .collect();

    ranked.sort_by(|(a_verified, a), (b_verified, b)| {
        b.priority
            .cmp(&a.priority)
            .then_with(|| b_verified.cmp(a_verified))
            .then_with(|| a.enqueued_at.cmp(&b.enqueued_at))
            .then_with(|| a.envelope_id.cmp(&b.envelope_id))
    });

    ranked.into_iter().map(|(_, entry)| entry).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;
    use std::time::Instant;

    fn small_params(delay: u64) -> VdfParams {
        // 128-bit primes (256-bit modulus): fast enough for the normal test
        // suite. Explicitly *not* a production-target key size -- and per
        // the module docs, key size isn't the binding constraint here
        // anyway, since the factorization is known to whoever generates it.
        VdfParams::generate(&mut OsRng, 128, delay)
    }

    #[test]
    fn test_vdf_proof_verifies_for_honest_evaluation() {
        let params = small_params(300);
        let seed = b"epoch-seed-round-1";
        let envelope_id = b"envelope-abc";

        let proof = evaluate(&params, seed, envelope_id);
        assert!(verify(&params, seed, envelope_id, &proof));

        // Wrong seed, wrong envelope id, or wrong delay must all fail.
        assert!(!verify(&params, b"epoch-seed-round-2", envelope_id, &proof));
        assert!(!verify(&params, seed, b"envelope-xyz", &proof));
        let wrong_delay = VdfParams {
            modulus: params.modulus.clone(),
            delay: params.delay + 1,
        };
        assert!(!verify(&wrong_delay, seed, envelope_id, &proof));
    }

    #[test]
    fn test_backdated_proof_is_rejected() {
        // The round requires 1000 sequential squarings.
        let real_params = VdfParams {
            modulus: small_params(0).modulus,
            delay: 1000,
        };
        let seed = b"epoch-seed-round-1";
        let envelope_id = b"envelope-abc";

        // An honest proof for the required delay verifies.
        let honest_proof = evaluate(&real_params, seed, envelope_id);
        assert!(verify(&real_params, seed, envelope_id, &honest_proof));

        // A party that only performed a fraction of the required sequential
        // work -- i.e. tried to "backdate" by claiming to have started
        // earlier than it actually did -- cannot produce a proof that
        // verifies against the real, larger required delay, even though its
        // own smaller-delay proof is perfectly valid on its own terms.
        let cheat_params = VdfParams {
            modulus: real_params.modulus.clone(),
            delay: 100,
        };
        let cheat_proof = evaluate(&cheat_params, seed, envelope_id);
        assert!(verify(&cheat_params, seed, envelope_id, &cheat_proof));
        assert!(
            !verify(&real_params, seed, envelope_id, &cheat_proof),
            "a proof for less than the required sequential work must not verify \
             against the required delay"
        );
    }

    #[test]
    fn test_vdf_evaluation_time_matches_configured_delay_parameter() {
        let params_1x = small_params(8_000);
        let params_2x = VdfParams {
            modulus: params_1x.modulus.clone(),
            delay: params_1x.delay * 2,
        };
        let seed = b"epoch-seed-timing";
        let envelope_id = b"envelope-timing";

        // Warm up (allocator/cache effects on the very first call are not
        // representative), then time each delay multiple times and take the
        // minimum -- standard microbenchmark practice: scheduling
        // interruptions can only add time, never subtract, so the minimum
        // across repeats is the closest approximation of true cost on a
        // shared/virtualized machine like the one running this test suite.
        evaluate(&params_1x, seed, envelope_id);

        let time_min = |params: &VdfParams| -> std::time::Duration {
            (0..5)
                .map(|_| {
                    let start = Instant::now();
                    evaluate(params, seed, envelope_id);
                    start.elapsed()
                })
                .min()
                .unwrap()
        };

        let elapsed_1x = time_min(&params_1x);
        let elapsed_2x = time_min(&params_2x);

        // Evaluation time should scale with the delay parameter -- assert
        // proportionality (with generous slack for scheduling noise on a
        // shared/virtualized machine) rather than an absolute wall-clock
        // bound, since absolute speed varies enormously by hardware (see
        // the module docs' "Measured costs").
        let ratio = elapsed_2x.as_secs_f64() / elapsed_1x.as_secs_f64().max(1e-9);
        assert!(
            (1.15..3.5).contains(&ratio),
            "doubling the delay parameter should roughly double evaluation time, got ratio {ratio} \
             ({elapsed_1x:?} -> {elapsed_2x:?})"
        );
    }

    #[test]
    fn test_ordering_integration_preserves_priority_tier_semantics() {
        let params = small_params(200);
        let seed = b"epoch-seed-round-1";

        let emergency_no_evidence = VdfOrderedEntry {
            envelope_id: [1u8; 32],
            priority: TxPriority::Emergency,
            enqueued_at: 5_000, // reported as "recent", i.e. self-reported-only
            proof: None,
        };
        let normal_verified_id = [2u8; 32];
        let normal_verified = VdfOrderedEntry {
            envelope_id: normal_verified_id,
            priority: TxPriority::Normal,
            enqueued_at: 1_000, // reported as "old", but this is VDF-backed anyway
            proof: Some(evaluate(&params, seed, &normal_verified_id)),
        };
        let low_no_evidence = VdfOrderedEntry {
            envelope_id: [3u8; 32],
            priority: TxPriority::Low,
            enqueued_at: 1,
            proof: None,
        };
        let normal_no_evidence_old = VdfOrderedEntry {
            envelope_id: [4u8; 32],
            priority: TxPriority::Normal,
            enqueued_at: 500, // older self-reported time than normal_verified
            proof: None,
        };

        let ordered = sort_for_dispatch(
            vec![
                low_no_evidence.clone(),
                normal_no_evidence_old.clone(),
                emergency_no_evidence.clone(),
                normal_verified.clone(),
            ],
            &params,
            seed,
        );

        // Priority tier dominates absolutely: Emergency first, then both
        // Normal entries, then Low -- regardless of VDF evidence or
        // self-reported timestamps.
        assert_eq!(ordered[0].priority, TxPriority::Emergency);
        assert_eq!(ordered[1].priority, TxPriority::Normal);
        assert_eq!(ordered[2].priority, TxPriority::Normal);
        assert_eq!(ordered[3].priority, TxPriority::Low);

        // Within the Normal tier: the entry with currently-valid VDF
        // evidence is preferred over the one with none, even though the
        // unverified entry claims an *older* self-reported enqueued_at --
        // self-reported age alone must not win against verified evidence.
        assert_eq!(ordered[1].envelope_id, normal_verified.envelope_id);
        assert_eq!(ordered[2].envelope_id, normal_no_evidence_old.envelope_id);
    }

    #[test]
    fn test_miller_rabin_agrees_with_known_small_primes_and_composites() {
        for p in [2u32, 3, 5, 7, 11, 13, 97, 7919] {
            assert!(
                is_probably_prime_deterministic(&BigUint::from(p)),
                "{p} should be classified prime"
            );
        }
        for c in [1u32, 4, 6, 8, 9, 10, 100, 7920] {
            assert!(
                !is_probably_prime_deterministic(&BigUint::from(c)),
                "{c} should be classified composite"
            );
        }
    }

    #[test]
    fn test_hash_to_prime_is_deterministic_and_prime() {
        let a = hash_to_prime(&[b"same-input"]);
        let b = hash_to_prime(&[b"same-input"]);
        assert_eq!(a, b);
        assert!(is_probably_prime_deterministic(&a));
        assert_eq!(a.bits(), CHALLENGE_PRIME_BITS);

        let c = hash_to_prime(&[b"different-input"]);
        assert_ne!(a, c);
    }

    #[test]
    fn test_no_vdf_evidence_anywhere_preserves_todays_fifo_behavior() {
        let params = small_params(50);
        let seed = b"epoch-seed";

        let older = VdfOrderedEntry {
            envelope_id: [10u8; 32],
            priority: TxPriority::Normal,
            enqueued_at: 100,
            proof: None,
        };
        let newer = VdfOrderedEntry {
            envelope_id: [20u8; 32],
            priority: TxPriority::Normal,
            enqueued_at: 200,
            proof: None,
        };

        let ordered = sort_for_dispatch(vec![newer.clone(), older.clone()], &params, seed);
        assert_eq!(ordered[0].envelope_id, older.envelope_id);
        assert_eq!(ordered[1].envelope_id, newer.envelope_id);
    }

    /// Not a correctness test -- measures actual squaring throughput on
    /// whatever machine runs it, per the module docs' "Measured costs".
    /// Run with `cargo test vdf_ordering::tests::measure -- --nocapture` to
    /// see the numbers.
    #[test]
    fn measure_vdf_squaring_throughput() {
        let params = VdfParams::generate(&mut OsRng, 512, 0); // 1024-bit modulus
        let x = derive_input(&params.modulus, b"bench-seed", b"bench-envelope");

        let squarings = 3000u32;
        let start = Instant::now();
        let mut y = x.clone();
        for _ in 0..squarings {
            y = (&y * &y) % &params.modulus;
        }
        let elapsed = start.elapsed();
        std::hint::black_box(&y);

        let per_squaring = elapsed / squarings;
        let profile = if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        };
        println!(
            "measured: {squarings} sequential 1024-bit modular squarings in {elapsed:?} \
             ({per_squaring:?}/squaring, {profile} build, this machine -- see module docs' \
             \"Measured costs\" for how to interpret this)"
        );
        assert!(elapsed.as_nanos() > 0);
    }
}
