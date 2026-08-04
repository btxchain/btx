// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_TYPED_H
#define BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_TYPED_H

#include <matmul/matmul_v4_rc_alg_hash.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Version-12 typed use of the frozen Poseidon2-GL12 permutation.
 *
 * V11 initializes the capacity to zero for both variable-length Fiat-Shamir
 * hashes and row leaves.  Consequently, a two-cell row can have exactly the
 * same padded permutation input as a transcript draw.  This V12 foundation
 * assigns every semantic hash role a distinct initial capacity tuple:
 *
 *   ("BTXTYPED", role, protocol=12, typed_hash_version=1).
 *
 * Witness data is absorbed only into rate lanes [0,8), so it cannot overwrite
 * the tuple before the first permutation; all twelve state lanes then evolve
 * normally across later sponge blocks. V11 is deliberately not reinterpreted:
 * these functions and the provider's BeginTyped entry point are additive until
 * prove, verify, recursive replay and wire version migrate together.
 *
 * SECURITY SCOPE: distinct initial states remove the concrete V11
 * identical-permutation-input defect. They do not, alone, instantiate the
 * SAFE/SAFECore API or prove NIROP/BCS composition. A theorem-bearing migration
 * must additionally pin the IO-pattern/domain-tag derivation and continuous
 * absorb/squeeze transcript state, then migrate native and recursive consumers
 * together. The hard-false markers at the bottom make that distinction
 * executable.
 */
namespace matmul::v4::rc::alg_hash_typed {

namespace gf = gkr_field;
namespace ah = alg_hash;

inline constexpr uint32_t kTypedHashVersionV1 = 1;
inline constexpr uint32_t kProtocolVersionV12 = 12;
inline constexpr gf::Fp kCapacityMagicV1 =
    UINT64_C(0x4254585459504544); // "BTXTYPED"

enum class RoleV12 : uint32_t {
    MerkleRowLeaf = 1,
    MerkleFoldLeaf = 2,
    MerkleInternalNode = 3,
    TranscriptShapeCommit = 4,
    TranscriptAirLambda = 5,
    TranscriptFriSeed = 6,
    TranscriptOodZ1 = 7,
    TranscriptOodZ2 = 8,
    TranscriptOodEvaluations = 9,
    TranscriptBatchSeed = 10,
    TranscriptBatchCoefficient = 11,
    TranscriptDeepWeight = 12,
    TranscriptFoldState = 13,
    TranscriptFoldBeta = 14,
    TranscriptQuerySeed = 15,
    TranscriptQueryCandidate = 16,
    TranscriptPadding = 17,
    ReceiptCommitment = 18,
    ProgramTableCommitment = 19,
    ApplicationStatementCommitment = 20,
};

inline constexpr uint32_t kRoleCountV12 = 20;
using CapacityIvV12 = std::array<gf::Fp, ah::kAlgHashCapacity>;

/** Canonical role inventory. Enum values and order are consensus-visible. */
[[nodiscard]] const std::array<RoleV12, kRoleCountV12>& AllRolesV12();
[[nodiscard]] bool IsKnownRoleV12(RoleV12 role);

/**
 * Fold leaves and internal nodes have fixed-width encodings and are rejected
 * by the generic sponge API.  All remaining roles, including row leaves, use
 * the injective variable-length 10* encoding.
 */
[[nodiscard]] bool IsVariableSpongeRoleV12(RoleV12 role);

/** Return the canonical four-lane capacity IV for one known role. */
[[nodiscard]] bool CapacityIvForRoleV12(
    RoleV12 role, CapacityIvV12& iv, std::string* why = nullptr);

/** Initialize a zero rate and the canonical role capacity. */
[[nodiscard]] bool InitializeStateV12(
    RoleV12 role, ah::State& state, std::string* why = nullptr);

/**
 * Typed variable-length sponge over Fp. Inputs are canonicalized before
 * add-absorption. Returns false for unknown or fixed-width-only roles.
 */
[[nodiscard]] bool SpongeHashFpV12(
    RoleV12 role, const std::vector<gf::Fp>& lanes,
    ah::Digest& digest, std::string* why = nullptr);

/** Variable-length row leaf: c0,c1,c2 per cell, then canonical row index. */
[[nodiscard]] ah::Digest RowLeafV12(
    const std::vector<gf::Fp3>& row, uint32_t index);

/** Fixed-width fold leaf: [c0,c1,c2,index] in rate, one permutation. */
[[nodiscard]] ah::Digest FoldLeafV12(
    const gf::Fp3& value, uint32_t index);

/** Fixed-width Merkle node: left[0..4), right[0..4), one permutation. */
[[nodiscard]] ah::Digest CompressV12(
    const ah::Digest& left, const ah::Digest& right);

/**
 * Column-streaming typed row hasher. Its output is field-identical to
 * RowLeafV12 while retaining only one state and partial rate block per row.
 */
class StreamingRowHasherV12
{
private:
    struct RowState {
        ah::State sponge{};
        std::array<gf::Fp, ah::kAlgHashRate> pending{};
        uint32_t pending_count{0};
    };

    std::vector<RowState> m_rows;
    uint32_t m_columns{0};
    bool m_finalized{false};

    static void AbsorbLane(RowState& row, gf::Fp value);

public:
    explicit StreamingRowHasherV12(uint32_t n_rows);

    [[nodiscard]] bool AbsorbColumn(
        const std::vector<gf::Fp3>& column,
        std::string* why = nullptr);
    [[nodiscard]] bool AbsorbColumnBlock(
        const std::vector<std::vector<gf::Fp3>>& block,
        size_t count, std::string* why = nullptr);
    [[nodiscard]] bool Finalize(
        std::vector<ah::Digest>& digests,
        std::string* why = nullptr);

    [[nodiscard]] uint32_t Rows() const;
    [[nodiscard]] uint32_t Columns() const;
    [[nodiscard]] uint64_t WorkingSetBytes() const;
    [[nodiscard]] static uint64_t WorkingSetBytesForRows(uint32_t n_rows);
};

// Fail-closed migration markers. This file supplies the primitive and
// accelerated foundation only; it does not change active V11 semantics.
inline constexpr bool kActiveBackendMigratedV12 = false;
inline constexpr bool kRecursiveReplayMigratedV12 = false;
inline constexpr bool kSafeCoreTagDerivationImplementedV12 = false;
inline constexpr bool kContinuousTranscriptImplementedV12 = false;
inline constexpr bool kTypedHashAuthorityReadyV12 =
    kActiveBackendMigratedV12 &&
    kRecursiveReplayMigratedV12 &&
    kSafeCoreTagDerivationImplementedV12 &&
    kContinuousTranscriptImplementedV12;

} // namespace matmul::v4::rc::alg_hash_typed

#endif // BTX_MATMUL_MATMUL_V4_RC_ALG_HASH_TYPED_H
