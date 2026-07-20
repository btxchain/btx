// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_H

#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// REAL FRI PCS for ENC_RC Section-2 / MASTER PACKET M1 (proof version 2).
//
// Pipeline:
//   1. Treat input as degree-<n coefficients (n = next_pow2(len)).
//   2. LDE: zero-pad coeffs to N = blowup * n and NTT-evaluate on the
//      size-N multiplicative subgroup of Goldilocks (embedded in Fp2).
//   3. Merkle-commit (SHA256d) the LDE evaluations.
//   4. Multi-round FRI fold: next[i] = even[i] + β * odd[i] from pair
//      (2i, 2i+1); commit each folded layer (commit-then-challenge).
//   5. Derive kRCFriNumQueries indices from FS; for each query open the
//      fold path at EVERY layer and check the fold equation.
//
// Soundness (conservative unique-decoding / Reed–Solomon proximity, ROM):
//   Per-query rejection bound ≤ ρ = 1/blowup = 1/8 = 2^{-3}.
//   ε_queries ≤ ρ^k = 2^{-3k}.
//   Fold/FS algebraic error ≤ (#rounds)·deg/|Fp2| ≤ O(log N)·2^{-128} (negligible).
//   After grinding G = 2^{kRCFriGrindingBits} FS tries (PoW-bound seed):
//     ε_net ≤ 2^g · 2^{-3k}.
//   Target ε_net ≤ 2^{-64}  ⇒  k ≥ ceil((g + 64) / 3).
//   With g = 32: k ≥ 32. We set kRCFriNumQueries = 40 for margin:
//     ε_net ≤ 2^{32} · 2^{-120} = 2^{-88} ≤ 2^{-64}.
//
// Assumptions (honest): Reed–Solomon proximity at unique-decoding radius,
// commit-then-challenge Fiat–Shamir in the random-oracle model, and that
// `fs_seed` is already SHA256d-bound to the winning block digest / pow_bind
// (caller responsibility in GKR). List-decoding (≈√ρ per query) would need
// ~80 queries for the same 2^{-64} net target — see the soundness doc.
//
// Proof size is O(queries × log N × 32) Merkle openings — NOT the LDE
// witness vector. Flipping an LDE eval and re-using old openings MUST fail.

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCFriProofMagic = 0x46524933u; // 'FRI3'
inline constexpr uint32_t kRCFriProofVersion = 2;
inline constexpr char kRCFriDomainTag[] = "BTX_RC_FRI_V2";

/** LDE blowup factor B; rate ρ = 1/B. */
inline constexpr uint32_t kRCFriBlowup = 8;
/**
 * Query count k from unique-decoding bound (see header formula).
 * g=32, ceil((32+64)/3)=32; use 40 for margin → claimed ε_net ≤ 2^{-88}.
 */
inline constexpr uint32_t kRCFriNumQueries = 40;
/** PoW grinding bits assumed subtracted from the FS bound (G ≤ 2^g). */
inline constexpr uint32_t kRCFriGrindingBits = 32;

/**
 * Human-readable soundness statement (must match FriSoundnessBoundBits()).
 */
inline constexpr char kRCFriSoundnessStatement[] =
    "FRI REAL (v2): LDE blowup=8, k=40 queries, g=32 grinding; "
    "unique-decoding ε_net ≤ 2^{32}·(1/8)^{40} = 2^{-88} ≤ 2^{-64} "
    "(ROM, RS proximity, commit-then-challenge; fs_seed PoW-bound by caller). "
    "COMPUTATIONAL — not ε=0.";

/** Soft budgets for Section-2 (toy/medium CPU). Not silicon rates. */
inline constexpr size_t kRCFriProofBytesBudget = 256 * 1024; // 256 KiB soft
inline constexpr double kRCFriVerifyBudgetS = 0.5;

struct FriMerklePath {
    uint32_t index{0};
    Fp2 leaf{};
    std::vector<uint256> siblings; // rootward
};

/** One fold-round opening: Merkle paths for the even/odd pair. */
struct FriFoldStep {
    uint32_t even_index{0}; // = 2*i on this layer
    Fp2 even{};
    Fp2 odd{};
    std::vector<uint256> even_siblings;
    std::vector<uint256> odd_siblings;
};

/** Full fold-path opening for one FS query index on layer 0. */
struct FriQueryOpening {
    uint32_t index{0}; // layer-0 LDE index
    std::vector<FriFoldStep> steps; // one per fold round (layers 0..R-1)
};

struct FriLayerCommit {
    uint256 root{};
    uint32_t n_leaves{0};
};

struct FriProof {
    uint32_t version{kRCFriProofVersion};
    /** Optional grinding nonce absorbed into FRI FS (factor if unused). */
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    /** Coefficient count after pow2 pad (before LDE). */
    uint32_t n_coeffs{0};
    /** Layer 0 = LDE commitment; last layer is the final constant. */
    std::vector<FriLayerCommit> layers;
    /** Final constant after fold (prover claim; must match last layer). */
    Fp2 final_value{};
    /** Fold challenges (echoed; verifier re-derives from FS). */
    std::vector<Fp2> fold_challenges;
    /** Per-query fold-path openings — NOT the full LDE witness. */
    std::vector<FriQueryOpening> queries;
};

struct FriCommitResult {
    FriProof proof;
    /** Prover-only LDE evaluations (layer 0). NEVER shipped in proof bytes. */
    std::vector<Fp2> lde_evals;
    /** Prover-only folded layer evaluations (including layer 0). */
    std::vector<std::vector<Fp2>> layer_evals;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * LDE + Merkle commit + multi-round FRI fold + query openings.
 * `fs_seed` MUST already include PoW bind to the winning digest (GKR).
 * `pow_grind_nonce` is absorbed into FRI FS for optional grinding factor.
 */
[[nodiscard]] FriCommitResult FriCommitAndFold(const std::vector<Fp2>& coeffs,
                                               const uint256& fs_seed,
                                               uint64_t pow_grind_nonce = 0);

/** Open leaf `index` against a committed evaluation vector (prover helper). */
[[nodiscard]] FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals,
                                         uint32_t index);

[[nodiscard]] bool FriVerifyPath(const FriMerklePath& path, const uint256& root,
                                 uint32_t n_leaves);

/**
 * Verify FRI without the witness: re-derive fold challenges + query indices
 * from FS, open Merkle paths on every layer along each fold path, check fold
 * equations, and check the final constant. REJECT on any failure.
 */
[[nodiscard]] bool FriVerify(const FriProof& proof, const uint256& fs_seed,
                             std::string* why = nullptr);

[[nodiscard]] size_t SerializeFriProof(const FriProof& proof,
                                       std::vector<unsigned char>& out);
[[nodiscard]] std::optional<FriProof> DeserializeFriProof(
    const std::vector<unsigned char>& in);

/** Hash a single Fp2 leaf for Merkle (domain-tagged). */
[[nodiscard]] uint256 FriLeafHash(const Fp2& v, uint32_t index);
[[nodiscard]] uint256 FriNodeHash(const uint256& left, const uint256& right);

[[nodiscard]] uint32_t FriNextPow2(uint32_t n);

/**
 * Claimed soundness bits after grinding under the unique-decoding formula
 * in the header: 3*kRCFriNumQueries - kRCFriGrindingBits.
 */
[[nodiscard]] inline int FriSoundnessBoundBits()
{
    return static_cast<int>(3 * kRCFriNumQueries - kRCFriGrindingBits);
}

/**
 * Forge-test helper: flip one LDE evaluation and rebuild only layer-0 root
 * while keeping old query openings — FriVerify MUST reject. Used by tests
 * to show forged low-degree / inconsistent witnesses fail.
 */
[[nodiscard]] bool FriForgeFlippedEvalMustFail(const FriCommitResult& honest,
                                               const uint256& fs_seed,
                                               uint32_t flip_index,
                                               std::string* why = nullptr);

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_H
