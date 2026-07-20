// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_FRI_H
#define BTX_MATMUL_MATMUL_V4_RC_FRI_H

#include <matmul/matmul_v4_rc_gkr_field_ext.h>
#include <uint256.h>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// REAL FRI PCS for ENC_RC Section-2 (proof version 3) — M6/Fable + DEEP/OOD.
//
// Pipeline: LDE (blowup) → Merkle commit → DEEP out-of-domain sample →
// multi-round fold → FS queries with per-layer fold-path openings + DEEP
// quotient openings at the same indices. Witness LDE is NEVER shipped.
//
// ============================================================================
// SOUNDNESS PARAMETERS (M6 — Fable cross-check; code and statement MUST agree)
// ============================================================================
// Shipped: g=40, Fp2, blowup B=16 (ρ=1/16), Q=116 unique decoding.
// FriSoundnessBoundBits() = 65. See soundness note.
//
// DEEP/OOD (ePrint 2019/336; DEEP-ALI practice): after committing P, draw z∉D,
// claim v=P(z), commit quotient Q=(P−v)/(X−z), open Q at FRI query sites,
// check P(x)=Q(x)·(x−z)+v. Closes "proximity ≠ exact evaluation" for P(z).
//
// Conjectured ρ^Q: -DBTX_RC_FRI_CONJECTURED_BOUND=1 (default OFF, never consensus).

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCFriProofMagic = 0x46524934u; // 'FRI4'
inline constexpr uint32_t kRCFriProofVersion = 3;
inline constexpr char kRCFriDomainTag[] = "BTX_RC_FRI_V3";

inline constexpr uint32_t kRCFriBlowup = 16;
inline constexpr uint32_t kRCFriGrindingBits = 40;
inline constexpr uint32_t kRCFriNumQueries = 116;
inline constexpr uint32_t kRCFriNumQueriesBciKs20Optional = 53;

[[nodiscard]] inline int FriSoundnessBoundBits()
{
    constexpr uint64_t kLog2_32_17_Q32 = 3919317253ull;
    const uint64_t prod = static_cast<uint64_t>(kRCFriNumQueries) * kLog2_32_17_Q32;
    return static_cast<int>(prod >> 32) - static_cast<int>(kRCFriGrindingBits);
}

inline constexpr int kRCFriTargetSoundnessBits = 64;

inline constexpr char kRCFriSoundnessStatement[] =
    "FRI REAL (v3/M6/Fable+DEEP): blowup=16 (ρ=1/16), Q=116, g=40, Fp2; "
    "UNIQUE-DECODING α=17/32 ⇒ FriSoundnessBoundBits()=65; "
    "DEEP/OOD binds P(z) via quotient openings at query sites (ePrint 2019/336). "
    "NOT conjectured ρ^Q. ROM, commit-then-challenge; fs_seed PoW-bound. "
    "COMPUTATIONAL — not ε=0.";

inline constexpr size_t kRCFriProofBytesBudget = 1536 * 1024;
inline constexpr double kRCFriVerifyBudgetS = 2.0;

#if defined(BTX_RC_FRI_CONJECTURED_BOUND) && BTX_RC_FRI_CONJECTURED_BOUND
inline constexpr bool kRCFriConjecturedBoundEnabled = true;
#else
inline constexpr bool kRCFriConjecturedBoundEnabled = false;
#endif

struct FriMerklePath {
    uint32_t index{0};
    Fp2 leaf{};
    std::vector<uint256> siblings;
};

struct FriFoldStep {
    uint32_t even_index{0};
    Fp2 even{};
    Fp2 odd{};
    std::vector<uint256> even_siblings;
    std::vector<uint256> odd_siblings;
};

struct FriQueryOpening {
    uint32_t index{0};
    std::vector<FriFoldStep> steps;
    /** DEEP: Q(x) leaf at the same index + Merkle siblings into deep_quot_root. */
    Fp2 deep_quot_leaf{};
    std::vector<uint256> deep_quot_siblings;
};

struct FriLayerCommit {
    uint256 root{};
    uint32_t n_leaves{0};
};

struct FriProof {
    uint32_t version{kRCFriProofVersion};
    uint64_t pow_grind_nonce{0};
    uint32_t blowup{kRCFriBlowup};
    uint32_t n_coeffs{0};
    std::vector<FriLayerCommit> layers;
    Fp2 final_value{};
    std::vector<Fp2> fold_challenges;
    std::vector<FriQueryOpening> queries;
    /** DEEP/OOD (v3). has_deep=false only for nested quotient FRI. */
    bool has_deep{false};
    Fp2 deep_z{};
    Fp2 deep_eval{};
    uint256 deep_quot_root{};
    uint32_t deep_quot_n_leaves{0};
    /** Low-degree FRI on Q=(P−v)/(X−z); no recursive DEEP. */
    std::shared_ptr<FriProof> deep_quot_fri;
};

struct FriCommitResult {
    FriProof proof;
    std::vector<Fp2> lde_evals;
    std::vector<std::vector<Fp2>> layer_evals;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

[[nodiscard]] FriCommitResult FriCommitAndFold(const std::vector<Fp2>& coeffs,
                                               const uint256& fs_seed,
                                               uint64_t pow_grind_nonce = 0,
                                               bool enable_deep = true);

[[nodiscard]] FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals, uint32_t index);

[[nodiscard]] bool FriVerifyPath(const FriMerklePath& path, const uint256& root,
                                 uint32_t n_leaves);

[[nodiscard]] bool FriVerify(const FriProof& proof, const uint256& fs_seed,
                             std::string* why = nullptr);

[[nodiscard]] size_t SerializeFriProof(const FriProof& proof, std::vector<unsigned char>& out);
[[nodiscard]] std::optional<FriProof> DeserializeFriProof(const std::vector<unsigned char>& in);

[[nodiscard]] uint256 FriLeafHash(const Fp2& v, uint32_t index);
[[nodiscard]] uint256 FriNodeHash(const uint256& left, const uint256& right);

[[nodiscard]] uint32_t FriNextPow2(uint32_t n);

[[nodiscard]] bool FriForgeFlippedEvalMustFail(const FriCommitResult& honest,
                                               const uint256& fs_seed, uint32_t flip_index,
                                               std::string* why = nullptr);

[[nodiscard]] inline bool FriClaimedBitsMeetTarget()
{
    return FriSoundnessBoundBits() >= kRCFriTargetSoundnessBits &&
           kRCFriNumQueries >= 116u && kRCFriBlowup == 16u &&
           kRCFriGrindingBits == 40u && !kRCFriConjecturedBoundEnabled;
}

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_H
