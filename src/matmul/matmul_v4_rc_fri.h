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

// Minimal transparent FRI-style PCS scaffold for ENC_RC Section-2.
//
// Commit a 1D evaluation vector (MLE coeffs or evals) WITHOUT shipping the
// witness. Open at Fiat–Shamir challenge points. Proof size is O(log n)
// Merkle commitments + openings (SHA256 layers) — NOT every Extract tile.
//
// SCAFFOLD honesty: this is a CPU-green transparent fold suitable for CI and
// asymptotic sizing. It is NOT a production-complete FRI/STARK with coded
// Reed–Solomon proximity proofs, grinding-hardened queries, or audited
// soundness. See doc/btx-matmul-v4.5-rc-succinct-proof-soundness-2026-07-20.md.

namespace matmul::v4::rc {

using gkr_field::Fp2;

inline constexpr uint32_t kRCFriProofMagic = 0x46524933u; // 'FRI3'
inline constexpr uint32_t kRCFriProofVersion = 1;
inline constexpr char kRCFriDomainTag[] = "BTX_RC_FRI_V1";

/** Soft budgets for the Section-2 scaffold (toy/medium CPU). Not silicon rates. */
inline constexpr size_t kRCFriProofBytesBudget = 256 * 1024; // 256 KiB soft
inline constexpr double kRCFriVerifyBudgetS = 0.5;

struct FriMerklePath {
    uint32_t index{0};
    Fp2 leaf{};
    std::vector<uint256> siblings; // rootward
};

struct FriLayerCommit {
    uint256 root{};
    uint32_t n_leaves{0};
};

struct FriProof {
    uint32_t version{kRCFriProofVersion};
    /** Layer 0 = commit of the original evaluation vector (pow2-padded). */
    std::vector<FriLayerCommit> layers;
    /** Final constant after fold (prover claim). */
    Fp2 final_value{};
    /** Openings of layer-0 at FS query indices (Merkle paths). */
    std::vector<FriMerklePath> openings;
    /** Fold challenges used (echoed for verify; also re-derived from FS). */
    std::vector<Fp2> fold_challenges;
};

struct FriCommitResult {
    FriProof proof;
    /** Retained only by prover; NEVER shipped in the proof bytes. */
    std::vector<Fp2> evals_pow2;
    size_t proof_bytes{0};
    bool ok{false};
    std::string note;
};

/**
 * Commit evals (padded to next power of 2) into a Merkle tree of SHA256d leaf
 * hashes. Folds layers with FS challenges from `fs_seed` until one value.
 * Does not include `evals` in the serialized proof — only roots + openings.
 */
[[nodiscard]] FriCommitResult FriCommitAndFold(const std::vector<Fp2>& evals,
                                               const uint256& fs_seed,
                                               uint32_t n_openings = 2);

/** Open leaf `index` against layer-0 commitment (prover-side helper). */
[[nodiscard]] FriMerklePath FriOpenIndex(const std::vector<Fp2>& evals_pow2,
                                         uint32_t index);

[[nodiscard]] bool FriVerifyPath(const FriMerklePath& path, const uint256& root,
                                 uint32_t n_leaves);

/**
 * Verify FRI scaffold: Merkle openings + fold consistency to final_value.
 * Does NOT re-materialize the witness vector.
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

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_FRI_H
