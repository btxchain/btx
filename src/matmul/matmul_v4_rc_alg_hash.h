// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H
#define BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

// ALGEBRAIC HASH over Goldilocks — Poseidon2 (ePrint 2023/323), the fixed
// instance `AlgHash` of the Stage-C spec §1 (scratchpad/stage-c-buildable-spec.md):
//
//   field  Goldilocks p = 2^64 − 2^32 + 1        (matmul_v4_rc_gkr_field.h)
//   t = 12 lanes (rate 8 + capacity 4)           d = 7 S-box (x ↦ x^7, gcd(7,p−1)=1)
//   R_F = 8 full rounds (4 initial + 4 final)    R_P = 22 partial rounds
//   digest = 4 Fp lanes (256-bit, 128-bit collision floor)
//
// Round structure (external layer M_E applied once up front — the 2023/323
// refinement): M_E; 4×{+RC_ext, x^7 all lanes, M_E}; 22×{+RC_int on lane 0,
// x^7 on lane 0, M_I}; 4×{+RC_ext, x^7 all lanes, M_E}. Total S-boxes
// 8·12 + 22 = 118 — every AIR constraint is either the degree-7 identity
// y = x^7 or a degree-1 linear-layer identity (max alg_degree = 7).
//
// M_E is the FROZEN Poseidon2 block-circulant circ(2·M4, M4, M4) over three
// 4-lane blocks with the fixed MDS M4 = [5 7 1 3; 4 6 1 1; 1 3 5 7; 1 1 4 6].
// M_I = J + diag(μ) (all-ones plus diagonal). μ, the 118 round constants and
// the node/leaf capacity domain seeds are all derived deterministically from
// the single frozen domain tag by a SHA256d counter-XOF with unbiased
// rejection sampling (SampleFp, spec §1.5/§1.6) — pinned by code, not by a
// data blob; the generated tables are frozen by checksum in the unit tests
// (matmul_v4_rc_alg_hash_tests.cpp).

namespace matmul::v4::rc::alg_hash {

using gkr_field::Fp;
using gkr_field::Fp3;

/** State width t = rate + capacity. */
inline constexpr uint32_t kAlgHashT = 12;
inline constexpr uint32_t kAlgHashRate = 8;
inline constexpr uint32_t kAlgHashCapacity = 4;
/** Digest width (Fp lanes): 256 bits, ≥ 2·128-bit collision resistance. */
inline constexpr uint32_t kAlgHashDigestLen = 4;
/** Full rounds R_F (split 4 initial + 4 final) and partial rounds R_P. */
inline constexpr uint32_t kAlgHashFullRounds = 8;
inline constexpr uint32_t kAlgHashPartialRounds = 22;
/** S-box power d; gcd(7, p−1) = 1 so x ↦ x^7 is a bijection on Fp. */
inline constexpr uint32_t kAlgHashSboxPower = 7;
/** Single frozen domain tag for ALL derived constants of this primitive. */
inline constexpr char kAlgHashDomainTag[] = "BTX_ALGHASH_P2_GL12_V1";

using State = std::array<Fp, kAlgHashT>;
using Digest = std::array<Fp, kAlgHashDigestLen>;

/** Deterministically generated constant tables (spec §1.4–§1.6). */
struct AlgHashConstants {
    /** External round constants RC_ext[r][i], r ∈ [0, R_F), i ∈ [0, t). */
    std::array<std::array<Fp, kAlgHashT>, kAlgHashFullRounds> rc_ext{};
    /** Internal round constants RC_int[r], r ∈ [0, R_P) (lane 0 only). */
    std::array<Fp, kAlgHashPartialRounds> rc_int{};
    /** Diagonal μ of the internal matrix M_I = J + diag(μ); μ_i ∉ {0, −1}. */
    std::array<Fp, kAlgHashT> mu{};
    /** Capacity domain seed D for 2→1 node compression. */
    Fp node_domain{0};
    /** Capacity domain seed Le for leaf hashing (Le ≠ D). */
    Fp leaf_domain{0};
};

/** Generated-once tables (thread-safe lazy init; deterministic re-derivation). */
[[nodiscard]] const AlgHashConstants& GetAlgHashConstants();

/**
 * External linear layer M_E = circ(2·M4, M4, M4): per-block y_b = M4·s_b,
 * then output block b = y_b + Σ_b y_b. Exposed for the AIR layer identities
 * and the invertibility/MDS unit tests.
 */
void ApplyExternalMatrix(State& s);

/** Internal linear layer M_I: out_i = σ + μ_i·s_i with σ = Σ_j s_j. */
void ApplyInternalMatrix(State& s);

/** The Poseidon2 permutation on Fp^12 (spec §1.2), in place. */
void Permute(State& s);

/**
 * Explicit inverse permutation (each layer inverted in reverse order; the
 * inverse S-box is x ↦ x^e with e = 7^{-1} mod (p−1)). Test/audit primitive —
 * proves Permute is a bijection; not used on any hashing path.
 */
void InversePermute(State& s);

/**
 * Fixed 2→1 Merkle compression (single permutation call):
 * state = [L0..L3, R0..R3, D, 0, 0, 0]; Permute; return state[0..4).
 */
[[nodiscard]] Digest Compress(const Digest& left, const Digest& right);

/**
 * Leaf hash of one Fp3 value bound to its domain index:
 * state = [v.c0, v.c1, v.c2, Fp(index), Le, 0,0,0, 0,0,0,0]; Permute;
 * return state[0..4). Le ≠ D gives node/leaf domain separation.
 */
[[nodiscard]] Digest LeafHash(const Fp3& v, uint32_t index);

/**
 * Row leaf: binds a whole row of W Fp3 column values plus the index via the
 * variable-length sponge (3W + 1 absorbed Fp elements: c0,c1,c2 per column
 * in column order, then Fp(index)).
 */
[[nodiscard]] Digest LeafHashRow(const std::vector<Fp3>& row, uint32_t index);

/**
 * Column-streaming form of LeafHashRow for a fixed row domain.  The prover can
 * process one LDE column at a time while retaining only one sponge state and
 * one partial rate block per row.  Finalize appends the row index and exact
 * 10* padding, producing byte/field-identical LeafHashRow digests.
 */
class StreamingRowHasher
{
private:
    struct RowState {
        State sponge{};
        std::array<Fp, kAlgHashRate> pending{};
        uint32_t pending_count{0};
    };

    std::vector<RowState> m_rows;
    uint32_t m_columns{0};
    bool m_finalized{false};

public:
    explicit StreamingRowHasher(uint32_t n_rows);

    [[nodiscard]] bool AbsorbColumn(
        const std::vector<Fp3>& column,
        std::string* why = nullptr);
    [[nodiscard]] bool Finalize(
        std::vector<Digest>& digests,
        std::string* why = nullptr);
    [[nodiscard]] uint32_t Rows() const;
    [[nodiscard]] uint32_t Columns() const;
    [[nodiscard]] uint64_t WorkingSetBytes() const;
    [[nodiscard]] static uint64_t WorkingSetBytesForRows(
        uint32_t n_rows);
};

/**
 * Variable-length sponge over Fp (rate 8, capacity 4, overwrite-free
 * add-absorb, 10*-padding over Fp: append 1 then 0s to a rate multiple).
 * Digest = state[0..4) after the final absorb permutation.
 */
[[nodiscard]] Digest SpongeHashFp(const std::vector<Fp>& xs);

/** Fp3 list absorption: each element as three lanes c0, c1, c2 (3m Fp total). */
[[nodiscard]] Digest SpongeHashFp3(const std::vector<Fp3>& xs);

// ===========================================================================
// PR-89: 384-bit binding-digest MODE — OPTIONAL high-margin config.
//
// STATUS: NOT required under the BTX threat model. It is a cheap, additive,
// env-selectable margin knob. The DEFAULT and shipped consensus path is the
// 256-bit binding digest (rate 8 / capacity 4 / digest 4), which is UNCHANGED
// and byte-identical.
//
// Why the 256-bit path already suffices: BTX tensor-mining is far costlier than
// Bitcoin SHA hashing, so the realistic per-block proof-grind budget is
// q <= ~78 (hash-rate x block/dispute window, tensor-mining as the primary
// anchor on attackable blocks), NOT the Bitcoin-scale q ~ 94-100. The shipped
// package (Q136 + enforced per-squeeze grind g=40 + A2 dual-lane + 256-bit
// c=128) gives the binding floor 2c - 2q = 256 - 2*78 = 100 at q=78, so the
// >= 100-bit target holds WITHOUT widening the digest. The 384-bit mode is only
// of interest for the paranoid q > 78 regime that BTX's mining cost precludes.
//
// What this mode does: it repartitions the SAME frozen Poseidon2 t=12
// permutation (identical M_E, M_I, RC tables, R_F=8/R_P=22, 118 S-boxes) as a
// rate-6 / capacity-6 sponge and squeezes a 6-lane (= 384-bit) digest. rate+cap
// = 6+6 = 12 = t, so no new permutation or constants are introduced. Absorb
// into rate lanes [0..6); capacity lanes [6..12) carry the domain seed (lane 6)
// plus a 384-mode tag (lane 7, cross-mode separation), otherwise 0; 10*-padding
// at rate 6. This lifts the output/birthday binding CAP (digest_bits - 2q) from
// 256-2q to 384-2q.
//
// HONEST SECURITY LABEL: birthday-192 / algebraic-128.
//   * The 6-lane capacity raises the GENERIC (birthday) sponge collision floor
//     to 2^192, and the 6-lane output raises the digest-width birthday term to
//     384-2q.
//   * BUT the round count (R_F=8, R_P=22) is dimensioned for a 128-bit
//     PERMUTATION (algebraic: interpolation / Groebner-basis) target and was
//     DELIBERATELY NOT re-dimensioned. So the algebraic collision floor stays
//     ~128, and the EFFECTIVE floor is min(192, 128) = 128 — the same algebraic
//     level as B256. Widening the capacity alone does not raise the algebraic
//     resistance of the permutation.
// A genuine 192-bit ALGEBRAIC floor would require re-dimensioning R_P upward
// (Poseidon ePrint 2019/458 §5.5, Poseidon2 ePrint 2023/323 §3; R_P is linear
// in the security level); that is intentionally out of scope here because the
// BTX threat model does not need it. This mode is additive and MODE-gated; no
// *_FormalSoundnessReady flag flips and B256 remains the verified default.

enum class BindingMode : uint32_t { B256 = 0, B384 = 1 };

inline constexpr uint32_t kBind384Rate = 6;
inline constexpr uint32_t kBind384Capacity = 6;
inline constexpr uint32_t kBind384DigestLen = 6;
static_assert(kBind384Rate + kBind384Capacity == kAlgHashT,
              "384 binding split must exactly fill the t=12 permutation width");
static_assert(kBind384Capacity * 64 / 2 >= 192,
              "6-lane capacity must give >= 192-bit generic BIRTHDAY floor");

/** 6-lane (384-bit) binding digest. */
using Digest384 = std::array<Fp, kBind384DigestLen>;

/** Digest lane count / bit width for a binding mode (Goldilocks lane = 64b). */
[[nodiscard]] constexpr uint32_t BindingDigestLen(BindingMode m)
{
    return m == BindingMode::B384 ? kBind384DigestLen : kAlgHashDigestLen;
}
[[nodiscard]] constexpr uint32_t BindingDigestBits(BindingMode m)
{
    return BindingDigestLen(m) * 64;
}
[[nodiscard]] constexpr uint32_t BindingCapacityLanes(BindingMode m)
{
    return m == BindingMode::B384 ? kBind384Capacity : kAlgHashCapacity;
}
/** GENERIC (birthday) sponge collision floor 2^(c/2), in bits: 128 / 192. */
[[nodiscard]] constexpr uint32_t BindingCapacityBirthdayFloorBits(BindingMode m)
{
    return BindingCapacityLanes(m) * 64 / 2;
}
/**
 * ALGEBRAIC (interpolation / Groebner) collision floor from the permutation
 * round count. Both modes reuse R_F=8/R_P=22, dimensioned for 128 bits and NOT
 * re-dimensioned, so this is 128 for BOTH modes.
 */
[[nodiscard]] constexpr uint32_t BindingAlgebraicFloorBits(BindingMode)
{
    return 128; // R_F=8, R_P=22 => 128-bit permutation target (unchanged)
}
/**
 * EFFECTIVE collision floor = min(birthday capacity, algebraic). B384 is
 * min(192, 128) = 128 — the SAME algebraic level as B256. B384's only real
 * gain is the digest-width birthday term 384-2q (see BindingBirthdayFloorBits).
 */
[[nodiscard]] constexpr uint32_t BindingEffectiveCollisionFloorBits(BindingMode m)
{
    const uint32_t a = BindingCapacityBirthdayFloorBits(m);
    const uint32_t b = BindingAlgebraicFloorBits(m);
    return a < b ? a : b;
}

/**
 * Process-wide active binding mode. Selector: env BTX_ALGHASH_BINDING_BITS
 * ("384" => B384; unset / anything else => B256). Read once and cached, so a
 * single node runs one consistent mode. B256 keeps every consensus path
 * byte-identical to today.
 */
[[nodiscard]] BindingMode ActiveBindingMode();

/**
 * AlgHash binding-digest birthday/collision CAP as a function of the adversary
 * hash-query budget q (in the soundness model's scaled unit): digest_bits-2q.
 * This is the exact floor PR-89 moves 256-2q -> 384-2q.
 */
[[nodiscard]] double BindingBirthdayFloorBits(uint32_t q, BindingMode m);

/**
 * 384-bit domain-separated sponge over the frozen t=12 permutation
 * (rate 6 / capacity 6). The domain seed occupies capacity lane 6; a fixed
 * 384-mode tag occupies lane 7. Injective 10*-padding at rate 6.
 */
[[nodiscard]] Digest384 SpongeHashFp384(const std::vector<Fp>& xs, Fp domain);

/** 2->1 node compression over 6-lane children under the node domain. */
[[nodiscard]] Digest384 Compress384(const Digest384& left,
                                    const Digest384& right);

/** Row leaf: Fp3 columns (c0,c1,c2 order) + index under the leaf domain. */
[[nodiscard]] Digest384 LeafHashRow384(const std::vector<Fp3>& row,
                                       uint32_t index);

} // namespace matmul::v4::rc::alg_hash

#endif // BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H
