// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_GKR_WIRING_H
#define BTX_MATMUL_MATMUL_V4_RC_GKR_WIRING_H

#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// CONSTRUCTION IV — copy / permutation (wiring) constraints (blueprint §4.x /
// §6.x cross-layer wiring, tile-tree binding companion).
//
// PROBLEM. Two committed vectors u, u' ∈ F^(2^ℓ) — canonically: layer L's
// extract_out column and layer L+1's input (operand) column — must be proven
// EQUAL (u = u'), or related by a FIXED PUBLIC permutation π (u'_j = u_{π(j)}),
// as an identity over the WHOLE Boolean hypercube. This must be a polynomial
// identity caught by random evaluation (Schwartz–Zippel), never a Fiat–Shamir
// hash chain: absorbing per-layer roots into FS binds *challenges* to the
// constructing routine's data but binds the data to NOTHING (§4.3
// insufficiency lemma / the F0 invalid assignment of §9).
//
// (a) EQUALITY (copy constraint). d := u − u' has multilinear extension
//     d̃ = ũ − ũ'. u = u' as vectors  ⟺  d̃ ≡ 0 on Fp2^ℓ. The checking
//     routine draws
//     ρ ∈ Fp2^ℓ (FS, after commitment) and checks ũ(ρ) = ũ'(ρ). Each side is
//     one MLE opening claim of a COMMITTED column — the opening backend is
//     Construction I (batched FRI + dual-OOD eval argument, §2.2/§2.4,
//     RCGkrOpeningClaim); this module produces the claims and, for direct /
//     test use, evaluates the MLEs itself over the raw columns.
//     SEPARATION (S2, Schwartz–Zippel): if d ≠ 0, d̃ is a nonzero ℓ-variate
//     multilinear (total degree ≤ ℓ), so it vanishes at uniform ρ ∈ Fp2^ℓ with
//     probability ≤ ℓ/|Fp2|. At the κ = 2^28 column cap (ℓ = 28):
//       28/2^128 = 2^-123.19 pre-grinding, 2^-83.19 after the repo's 2^40
//       grinding budget (S6) — clears the 2^-64 target with ≥ 19 bits margin.
//
// (b) PERMUTATION (grand product, Plonk-style; for fixed public wiring π such
//     as the free-transpose reuse of §1.2 when materialized, or any Λ-declared
//     copy with index remap). Claim: u'_j = u_{π(j)} for all j. For FS
//     challenges β, γ ∈ Fp2 drawn AFTER u, u' are committed:
//       Π_i (u_i + β·i + γ)  =  Π_j (u'_j + β·π(j) + γ),
//     enforced by a running-product column z with
//       z_0 = 1,   z_{i+1}·(u'_i + β·π(i) + γ) = z_i·(u_i + β·i + γ),
//       z_N = 1.
//     The pairing tags position i on the left and π(j) on the right, so the
//     honest case u'_j = u_{π(j)} matches factor j on the right with factor
//     π(j) on the left — the two products are equal TERM-BY-TERM as
//     multisets, hence z telescopes back to 1 exactly (completeness, ε = 0).
//     SEPARATION: the two products, as polynomials in (β, γ), are products of
//     monic-in-γ linear factors γ + β·tag + val; by unique factorization in
//     Fp2[β,γ] they are equal iff the multisets {(i, u_i)} and {(π(j), u'_j)}
//     coincide — which (π a bijection, tags injective: indices < 2^32 < p)
//     holds iff u'_j = u_{π(j)} for every j. Otherwise the difference is a
//     nonzero polynomial of total degree ≤ N and S2 gives acceptance
//     probability ≤ N/|Fp2| over (β, γ). At N = κ = 2^28:
//       2^28/2^128 = 2^-100.0 pre-grinding, 2^-60.0 after 2^40 grinding —
//       BELOW the 2^-64 target. Full-size columns therefore REQUIRE the
//       dual-challenge amplification (same argument as the dual-α LogUp,
//       §5.6): two independent (β, γ) pairs give (N/|Fp2|)² = 2^-200
//       pre-grinding, 2^-160 post — cleared with huge margin. The dual API
//       below is the recommended (and default-tested) form; single-challenge
//       is sufficient only for N ≤ 2^23 (2^-105 pre / 2^-65 post).
//     ZERO FACTORS (fail-closed, same posture as the LogUp denominators): if
//     any factor u_i + β·i + γ or u'_j + β·π(j) + γ is 0, the instance is
//     rejected with a resample reason — this is a completeness resample event
//     (probability ≤ 2N/|Fp2| per challenge pair), NEVER an accept path.
//
// CONSTRUCTING/CHECKING ROUTINE SPLIT. In the succinct v7 pipeline the z
// column is a
// committed column and the step/boundary identities are enforced at the
// batched-FRI evaluation points (Constructions I–III own commitment, opening
// and composition). This module owns the CONSTRAINT SYSTEM: it builds the
// columns/identities, emits the MLE opening claims, and provides a direct
// whole-hypercube checking routine used by unit tests and the integration shadow
// path. Consensus posture unchanged: arbiter OFF, heights INT32_MAX,
// RecomputeResidentCurriculumReference / RecomputeCoupledPuzzleReference
// untouched — ExactReplay remains the sole authority.
// ============================================================================

namespace matmul::v4::rc {

using gkr_field::Fp;
using gkr_field::Fp2;

inline constexpr uint32_t kRCGkrWiringVersion = 1;
inline constexpr char kRCGkrWiringDomainTag[] = "BTX_RC_GKR_WIRING_V1";

/** log2 |Fp2| = 2·log2(p), p = 2^64 − 2^32 + 1 (Goldilocks). */
inline constexpr double kRCGkrWiringFieldBits = 127.99999999932;
/** Repo grinding convention (S6): q_H = 2^40 RO queries; every FS term pays
 *  40 bits (matches FriSoundnessBoundBits()'s g = 40 subtraction). */
inline constexpr double kRCGkrWiringGrindBits = 40.0;
/** Column cap ℓ ≤ 28 (κ = 2^28, the Goldilocks 2-adicity wall, §2.1). */
inline constexpr uint32_t kRCGkrWiringMaxEll = kRCGkrColumnMaxLog2;

/** Single-challenge grand-product ceiling: N ≤ 2^23 keeps N/|Fp2| ≥ 105
 *  pre-grinding bits ⇒ ≥ 65 after grinding. Above it, use the dual form. */
inline constexpr uint64_t kRCGkrWiringSingleChallengeMaxN = uint64_t{1} << 23;

struct WiringVerifyResult {
    bool ok{false};
    std::string reason; // first failing check; empty or "ok" on success
};

// ----------------------------------------------------------------------------
// (a) EQUALITY constraint: u = u' via d̃(ρ) = ũ(ρ) − ũ'(ρ) = 0.
// ----------------------------------------------------------------------------

struct WiringEqualityConstraint {
    /** Logical (pre-padding) lengths. len_u ≠ len_v is a structural mismatch:
     *  deterministic reject (the Λ layout gives both sides the same shape). */
    uint64_t len_u{0};
    uint64_t len_v{0};
    /** ℓ = log2 of the common padded length (max of the two, rounded up). */
    uint32_t ell{0};
    /** Field-embedded columns, zero-padded to 2^ell. Padding both sides with
     *  the SAME value (0) keeps equality of pads unconditional; smuggling
     *  into pads is separately closed by the §2.5 suffix-zero sumcheck. */
    std::vector<Fp2> u;
    std::vector<Fp2> v;
};

/** Build from already field-embedded columns (values are moved in, then
 *  zero-padded to the common power of two). */
[[nodiscard]] WiringEqualityConstraint WiringEqualityFromFp2(std::vector<Fp2> u,
                                                             std::vector<Fp2> v);
/** int8 columns (O-columns: extract_out / expanded operands), embedded via
 *  FromSigned2 — injective, |x| ≤ 127 ≪ p. */
[[nodiscard]] WiringEqualityConstraint WiringEqualityFromInt8(const std::vector<int8_t>& u,
                                                              const std::vector<int8_t>& v);
/** int64 columns (T-columns: GEMM outputs / extract_in accumulators),
 *  embedded via FromSigned2 — injective, |x| < 2^62 ≪ p. */
[[nodiscard]] WiringEqualityConstraint WiringEqualityFromInt64(const std::vector<int64_t>& u,
                                                               const std::vector<int64_t>& v);

/**
 * Direct whole-hypercube check at a caller-supplied ρ ∈ Fp2^ell (FS-derived
 * AFTER both columns are committed — never before). Evaluates both MLEs over
 * the raw columns (test/shadow path; the succinct path consumes the
 * WiringEqualityOpeningClaims below instead).
 * COMPLETENESS: u = v (as padded vectors) passes for EVERY ρ, exactly.
 * SEPARATION: accepts a u ≠ v instance w.p. ≤ ell/|Fp2| over uniform ρ.
 */
[[nodiscard]] WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint& c,
                                                      const std::vector<Fp2>& rho);

/** Convenience: derive ρ from fs_seed (tagged SHA256d, label "wire_eq_rho",
 *  claim_index for domain separation across pairs) and verify. */
[[nodiscard]] WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint& c,
                                                      const uint256& fs_seed,
                                                      uint32_t claim_index);

/**
 * Succinct-path emission: the two MLE opening claims ũ(ρ) = e and ṽ(ρ) = e
 * (same point, same value — the checking routine compares the shared value, i.e.
 * d̃(ρ) = 0) for Construction I's eval argument. column_id_u / column_id_v
 * index the batched-FRI column list. Returns false (and sets why) on
 * structural mismatch. The claimed value is computed from the raw vectors —
 * on the full pipeline both claims are then certified against the COMMITTED
 * columns by EvalArgumentProve/Verify, so an invalid assignment cannot
 * substitute a different value (Theorem 2.2).
 */
[[nodiscard]] bool WiringEqualityOpeningClaims(const WiringEqualityConstraint& c,
                                               const std::vector<Fp2>& rho,
                                               uint32_t column_id_u, uint32_t column_id_v,
                                               std::vector<RCGkrOpeningClaim>& out,
                                               std::string* why = nullptr);

// ----------------------------------------------------------------------------
// (b) PERMUTATION constraint: u'_j = u_{π(j)} via Plonk-style grand product.
// ----------------------------------------------------------------------------

struct WiringPermutationConstraint {
    uint64_t n{0};
    /** Logical columns, length n (no padding: the running product is a length
     *  n+1 chain; padding rows would need explicit selector constraints). */
    std::vector<Fp2> u;
    std::vector<Fp2> v; // u' — claim: v[j] = u[pi[j]]
    /** Fixed PUBLIC permutation (known to the checking routine, e.g. Λ transpose
     *  remap). Must be a bijection [0,n) → [0,n); checked at verify. */
    std::vector<uint64_t> pi;
    /** FS challenges drawn AFTER u, v are committed. */
    Fp2 beta{};
    Fp2 gamma{};
    /** Running product, length n+1: z[0] = 1,
     *  z[i+1]·(v_i + β·π(i) + γ) = z[i]·(u_i + β·i + γ), z[n] = 1. */
    std::vector<Fp2> z;
    /** Build status. build_ok=false ⇒ fail-closed (e.g. zero factor:
     *  resample β/γ). Verify rejects such instances. */
    bool build_ok{false};
    std::string build_note;
};

/**
 * Constructing routine: builds the z column from the vectors + challenges. Fails
 * closed (build_ok=false) on: size mismatch, π out of range / not injective,
 * or any zero factor (numerator or denominator) — reason in build_note.
 */
[[nodiscard]] WiringPermutationConstraint BuildWiringPermutation(std::vector<Fp2> u,
                                                                 std::vector<Fp2> v,
                                                                 std::vector<uint64_t> pi,
                                                                 const Fp2& beta,
                                                                 const Fp2& gamma);

/**
 * Direct checking routine: structural checks (π bijection, sizes), boundary
 * z_0 = z_n = 1, and EVERY step identity
 *   z_{i+1}·(v_i + β·π(i) + γ) = z_i·(u_i + β·i + γ),
 * failing closed on any zero factor ("resample").
 * COMPLETENESS: v = π(u) (v_j = u_{π(j)} ∀j) with nonzero factors passes
 * exactly (the products agree term-by-term as multisets, so z telescopes
 * to 1). SEPARATION: a (u, v) with v ≠ π(u) passes w.p. ≤ n/|Fp2| over
 * uniform (β, γ); use the dual form for n > kRCGkrWiringSingleChallengeMaxN.
 */
[[nodiscard]] WiringVerifyResult VerifyWiringPermutation(const WiringPermutationConstraint& c);

/** Dual-challenge amplification (§5.6-style): two independent (β, γ) pairs;
 *  a false instance must survive both ⇒ (n/|Fp2|)². Mandatory at κ-sized
 *  columns (single-challenge nets only 2^-60 post-grinding at n = 2^28). */
struct WiringPermutationDual {
    WiringPermutationConstraint inst1;
    WiringPermutationConstraint inst2;
};

/** Challenges derived from fs_seed (labels "wire_perm_beta"/"wire_perm_gamma",
 *  instance indices 0/1; pair_index domain-separates multiple wirings under
 *  one seed). fs_seed MUST already bind the column commitments. */
[[nodiscard]] WiringPermutationDual BuildWiringPermutationDual(const std::vector<Fp2>& u,
                                                               const std::vector<Fp2>& v,
                                                               const std::vector<uint64_t>& pi,
                                                               const uint256& fs_seed,
                                                               uint32_t pair_index);

[[nodiscard]] WiringVerifyResult VerifyWiringPermutationDual(const WiringPermutationDual& d);

/** The row-major transpose wiring as an explicit permutation: producer tensor
 *  is rows×cols row-major; consumer reads the transpose, i.e.
 *  v[c·rows + r] = u[r·cols + c]. Returned π satisfies v[j] = u[π(j)]:
 *  π[c·rows + r] = r·cols + c. (In the v7 layout the transpose is FREE at the
 *  MLE level — M̃ᵀ(r,s) = M̃(s,r), §1.2 — this helper exists for wirings that
 *  materialize the transposed copy, e.g. device-side layouts.) */
[[nodiscard]] std::vector<uint64_t> MakeTransposePermutation(uint32_t rows, uint32_t cols);

// ----------------------------------------------------------------------------
// FS challenge derivation (tagged SHA256d; commit-then-challenge: the seed
// must bind all column commitments BEFORE any of these are drawn).
// ----------------------------------------------------------------------------

[[nodiscard]] Fp2 WiringChallengeFp2(const uint256& fs_seed, const char* label, uint32_t idx,
                                     uint32_t sub);
[[nodiscard]] std::vector<Fp2> WiringChallengePoint(const uint256& fs_seed, const char* label,
                                                    uint32_t idx, uint32_t ell);

/** Fp3 siblings (v7 episode path): 24-byte challenge derivation under a
 *  distinct domain tag — the Fp2 and Fp3 wiring transcripts never collide. */
[[nodiscard]] gkr_field::Fp3 WiringChallengeFp3(const uint256& fs_seed, const char* label,
                                                uint32_t idx, uint32_t sub);
[[nodiscard]] std::vector<gkr_field::Fp3> WiringChallengePoint3(const uint256& fs_seed,
                                                                const char* label, uint32_t idx,
                                                                uint32_t ell);

// ----------------------------------------------------------------------------
// Fp3 siblings of the equality / permutation constraints (v7 EPISODE path).
// Same constructions over ρ, (β, γ) ∈ Fp3 (|F| ≈ 2^192): equality S2 bound
// ℓ/|Fp3| (ℓ = 28 ⇒ 2^-187.19 pre / 2^-147.19 post-grind), dual grand product
// (n/|Fp3|)² (n = 2^28 ⇒ 2^-328 pre / 2^-288 post; single form 2^-124 post —
// above target over Fp3, but the DUAL MANDATE is structural and unchanged).
// The Fp2 module above remains for the legacy v6/coupled paths.
// ----------------------------------------------------------------------------

struct WiringEqualityConstraint3 {
    uint64_t len_u{0};
    uint64_t len_v{0};
    uint32_t ell{0};
    std::vector<gkr_field::Fp3> u;
    std::vector<gkr_field::Fp3> v;
};

[[nodiscard]] WiringEqualityConstraint3 WiringEquality3FromFp3(std::vector<gkr_field::Fp3> u,
                                                               std::vector<gkr_field::Fp3> v);
[[nodiscard]] WiringEqualityConstraint3 WiringEquality3FromInt8(const std::vector<int8_t>& u,
                                                                const std::vector<int8_t>& v);
[[nodiscard]] WiringEqualityConstraint3 WiringEquality3FromInt64(const std::vector<int64_t>& u,
                                                                 const std::vector<int64_t>& v);

[[nodiscard]] WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint3& c,
                                                      const std::vector<gkr_field::Fp3>& rho);
[[nodiscard]] WiringVerifyResult VerifyWiringEquality(const WiringEqualityConstraint3& c,
                                                      const uint256& fs_seed,
                                                      uint32_t claim_index);

struct WiringPermutationConstraint3 {
    uint64_t n{0};
    std::vector<gkr_field::Fp3> u;
    std::vector<gkr_field::Fp3> v; // u' — claim: v[j] = u[pi[j]]
    std::vector<uint64_t> pi;
    gkr_field::Fp3 beta{};
    gkr_field::Fp3 gamma{};
    std::vector<gkr_field::Fp3> z;
    bool build_ok{false};
    std::string build_note;
};

[[nodiscard]] WiringPermutationConstraint3 BuildWiringPermutation3(
    std::vector<gkr_field::Fp3> u, std::vector<gkr_field::Fp3> v, std::vector<uint64_t> pi,
    const gkr_field::Fp3& beta, const gkr_field::Fp3& gamma);

[[nodiscard]] WiringVerifyResult VerifyWiringPermutation(const WiringPermutationConstraint3& c);

struct WiringPermutationDual3 {
    WiringPermutationConstraint3 inst1;
    WiringPermutationConstraint3 inst2;
};

[[nodiscard]] WiringPermutationDual3 BuildWiringPermutationDual3(
    const std::vector<gkr_field::Fp3>& u, const std::vector<gkr_field::Fp3>& v,
    const std::vector<uint64_t>& pi, const uint256& fs_seed, uint32_t pair_index);

[[nodiscard]] WiringVerifyResult VerifyWiringPermutationDual(const WiringPermutationDual3& d);

// ----------------------------------------------------------------------------
// Separation bounds: −log2 of the SEPARATION PROBABILITY — the chance that a
// uniformly random challenge fails to detect an INVALID ASSIGNMENT (a pair of
// vectors that differ in ≥ 1 entry / are not related by π).
// ----------------------------------------------------------------------------

/** Equality: ℓ/|Fp2| ⇒ bits = log2|Fp2| − log2(ℓ) [− 40 if after_grinding].
 *  ℓ = 28 (κ column): 123.19 pre / 83.19 post. ℓ = 0: exact point compare,
 *  returns field bits as a conservative sentinel (actual probability 0). */
[[nodiscard]] double WiringEqualitySeparationBits(uint32_t ell, bool after_grinding);

/** Grand product: n/|Fp2| single, (n/|Fp2|)² dual.
 *  n = 2^28: single 100.0 pre / 60.0 post (BELOW target — do not ship);
 *            dual  200.0 pre / 160.0 post. n = 0: sentinel (field bits). */
[[nodiscard]] double WiringPermutationSeparationBits(uint64_t n, bool dual, bool after_grinding);

// ----------------------------------------------------------------------------
// Cross-layer binding helper (integration entry point): bind
// extract_out(L) == input(L+1) for every adjacent layer pair.
// ----------------------------------------------------------------------------

enum class WiringBindingKind : uint8_t {
    /** No shape-compatible input on the consumer: the pair's wiring is
     *  Λ-definitional (same column reference, §4.2) and needs no copy
     *  constraint — reported, never silently dropped. */
    Unbound = 0,
    /** Direct copy: consumer input has the producer's dims. */
    Equality = 1,
    /** Transposed reuse materialized as a copy: bound via the grand product
     *  with π = MakeTransposePermutation. */
    Permutation = 2,
};

struct WiringLayerBinding {
    size_t producer{0}; // index L into the wires vector
    size_t consumer{0}; // index L+1
    WiringBindingKind kind{WiringBindingKind::Unbound};
    /** 'A' or 'B': which consumer operand was bound ('\0' if Unbound). */
    char consumer_operand{'\0'};
    std::string note;
    /** kind == Equality. */
    WiringEqualityConstraint eq;
    /** kind == Permutation: raw columns + π; z is built at verify time from
     *  FS challenges (commit-then-challenge — z depends on β/γ). */
    std::vector<Fp2> u;
    std::vector<Fp2> v;
    std::vector<uint64_t> pi;
};

/**
 * For each adjacent pair (L, L+1) in the canonical Λ order, bind
 * wires[L].extract_out to the shape-designated input operand of wires[L+1]:
 *   1. consumer A with dims (m,k) == producer (m,n)  → Equality on A;
 *   2. else consumer B with dims (k,n) == producer   → Equality on B;
 *   3. else consumer A with dims == producer transposed → Permutation on A;
 *   4. else consumer B with dims == producer transposed → Permutation on B;
 *   5. else Unbound (Λ-definitional pair; note says so).
 * The VALUES are not consulted for the choice (shape only) — a value mismatch
 * is exactly what verification must catch, not silently re-route.
 */
[[nodiscard]] std::vector<WiringLayerBinding> BindAdjacentLayerWires(
    const std::vector<RCGkrV7WireWitness>& wires);

/**
 * Verify every binding: Equality via ρ = WiringChallengePoint(fs_seed,
 * "wire_eq_rho", pair_index, ell); Permutation via the dual grand product
 * (BuildWiringPermutationDual + VerifyWiringPermutationDual). fs_seed must
 * bind the column commitments (use RCGkrFsSeedV7 downstream). Unbound pairs
 * are counted in the reason string; they fail the result only when
 * fail_on_unbound is set (integration builds that require every pair to be
 * copy-constrained rather than Λ-definitional).
 */
[[nodiscard]] WiringVerifyResult VerifyLayerBindings(const std::vector<WiringLayerBinding>& bindings,
                                                     const uint256& fs_seed,
                                                     bool fail_on_unbound = false);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_GKR_WIRING_H
