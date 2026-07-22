// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H
#define BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>

#include <array>
#include <cstdint>
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
 * Variable-length sponge over Fp (rate 8, capacity 4, overwrite-free
 * add-absorb, 10*-padding over Fp: append 1 then 0s to a rate multiple).
 * Digest = state[0..4) after the final absorb permutation.
 */
[[nodiscard]] Digest SpongeHashFp(const std::vector<Fp>& xs);

/** Fp3 list absorption: each element as three lanes c0, c1, c2 (3m Fp total). */
[[nodiscard]] Digest SpongeHashFp3(const std::vector<Fp3>& xs);

} // namespace matmul::v4::rc::alg_hash

#endif // BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_H
