// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_FS_AIR_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_FS_AIR_H

#include <matmul/matmul_v4_rc_stage3_poseidon_air.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

/**
 * Proof-independent V12 SAFE transcript program for the PR95 verifier roles.
 *
 * This is an additive, fail-closed interface.  It fixes the complete call
 * schedule from public shape alone and supplies both:
 *
 *   (1) a native online-SAFE execution; and
 *   (2) a recursive-AIR witness projection whose Poseidon2 permutation rows
 *       use stage3_poseidon_air's executable quadratic chip.
 *
 * The construction deliberately does not change the active V11/Q192 proof.
 * It gives two independently tagged Q96 FRI lanes plus a separately tagged
 * AIR-quotient transcript.  Merkle roles remain in the disjoint typed
 * MerkleRowLeaf/MerkleFoldLeaf/MerkleInternalNode capacity class and are
 * forbidden in this FS program.
 *
 * Remaining authority work is explicit at the bottom: the proof payload
 * mapping, recursive IO-wiring constraints, pinned registry, NIROP/common-
 * commitment reduction and global theorem are not inferred from differential
 * host/AIR equality.
 */
namespace matmul::v4::rc::stage3_safe_v12_fs_air {

namespace gf = gkr_field;
namespace ah = alg_hash;
namespace aht = alg_hash_typed;
namespace safe = safe_v12;
namespace p2air = stage3_poseidon_air;

inline constexpr uint32_t kProtocolVersionV12 = 12;
inline constexpr uint32_t kFriLaneCountV12 = 2;
inline constexpr uint32_t kQueriesPerLaneV12 = 96;
inline constexpr uint32_t kOodCandidatesPerPointV12 = 2;
inline constexpr uint32_t kFriBlowupV12 = 16;
inline constexpr uint32_t kEventHeaderLanesV12 = 5;
inline constexpr gf::Fp kEventHeaderMagicV12 =
    UINT64_C(0x4254584653414952); // "BTXFSAIR"
inline constexpr uint32_t kProductionBatchColumnsV12 = 1750;
inline constexpr uint32_t kProductionFoldsV12 = 20;
inline constexpr uint32_t kProductionStaticDomainHeadroomRowsV12 = 56480;
inline constexpr uint32_t kProductionExpectedSafeAirRowsV12 = 2807;

enum class ChannelV12 : uint8_t {
    AirQuotient = 0,
    FriLane0 = 1,
    FriLane1 = 2,
};

enum class CallRoleV12 : uint16_t {
    AbsorbAirStatement = 1,
    BindAirLambda = 2,
    SqueezeAirLambda = 3,

    AbsorbFriPreamble = 10,
    BindBatchCoefficientVector = 11,
    SqueezeBatchCoefficientVector = 12,
    AbsorbBatchCoefficientVector = 13,
    BindZ1Candidates = 14,
    SqueezeZ1Candidates = 15,
    BindZ2Candidates = 16,
    SqueezeZ2Candidates = 17,
    AbsorbSelectedZ1 = 18,
    AbsorbSelectedZ2 = 19,
    AbsorbOodEvaluationCommitment = 20,
    BindDeepWeights = 21,
    SqueezeDeepWeights = 22,
    AbsorbDeepWeights = 23,
    AbsorbFoldRoot = 24,
    BindFoldBeta = 25,
    SqueezeFoldBeta = 26,
    BindQueryVector = 27,
    SqueezeQueryVector = 28,
};

enum class PayloadSourceV12 : uint8_t {
    None = 0,
    AirStatement = 1,
    FriPreamble = 2,
    DrawDescriptor = 3,
    BatchCoefficientFeedback = 4,
    SelectedZ1Feedback = 5,
    SelectedZ2Feedback = 6,
    OodEvaluationCommitment = 7,
    DeepWeightFeedback = 8,
    FoldRoot = 9,
};

struct ShapeV12 {
    uint32_t child_w{0};
    uint32_t child_n_rows{0};
    uint32_t child_quotient_len{0};
    uint32_t n_coeffs{0};
    uint32_t n_lde{0};
    uint32_t n_folds{0};

    friend bool operator==(const ShapeV12&, const ShapeV12&) = default;
};

struct CallSpecV12 {
    ChannelV12 channel{ChannelV12::AirQuotient};
    CallRoleV12 role{CallRoleV12::AbsorbAirStatement};
    aht::RoleV12 typed_role{aht::RoleV12::TranscriptAirLambda};
    safe::IoKindV12 io_kind{safe::IoKindV12::Absorb};
    PayloadSourceV12 payload_source{PayloadSourceV12::None};
    uint32_t ordinal{0};
    uint32_t items{0};
    uint32_t payload_lanes{0};
    uint32_t elements{0};
    std::string label;

    friend bool operator==(const CallSpecV12&,
                           const CallSpecV12&) = default;
};

struct ChannelManifestV12 {
    ChannelV12 channel{ChannelV12::AirQuotient};
    uint32_t lane{0};
    aht::RoleV12 capacity_role{
        aht::RoleV12::TranscriptAirLambda};
    std::vector<uint8_t> application_domain;
    std::vector<uint8_t> typed_domain;
    std::vector<CallSpecV12> calls;
    safe::TranscriptPatternManifestV12 safe_manifest;
    bool valid{false};
};

struct ManifestV12 {
    ShapeV12 shape{};
    ChannelManifestV12 air_quotient;
    std::array<ChannelManifestV12, kFriLaneCountV12> fri_lane{};
    std::array<aht::CapacityIvV12, 3> merkle_capacity{};
    std::array<aht::CapacityIvV12, 2> fs_capacity{};
    bool proof_independent{false};
    bool exact_pr95_roles{false};
    bool q96_lanes_domain_independent{false};
    bool merkle_fs_capacity_classes_disjoint{false};
    bool lane_seeds_derived_from_common_parent{false};
    bool proof_witness_cells_not_preprocessed{false};
    uint32_t proof_dependent_preprocessed_columns{0};
    uint64_t air_quotient_poseidon_rows{0};
    std::array<uint64_t, kFriLaneCountV12>
        fri_lane_poseidon_rows{};
    uint64_t total_poseidon_air_rows{0};
    uint64_t static_domain_headroom_rows{
        kProductionStaticDomainHeadroomRowsV12};
    uint64_t static_domain_margin_rows{0};
    bool fits_static_domain_headroom{false};
    bool production_reference_shape{false};
    bool production_reference_cost_pinned{false};
    bool valid{false};
    std::string note;
};

/** Parent-statement data shared by all three transcript channels. */
struct ParentStatementInputsV12 {
    ah::Digest parent_fs_seed{};
};

/**
 * Proof-owned ordinary witness cells. These are not parent public inputs and
 * never become preprocessed columns merely by entering the FS transcript.
 */
struct ProofWitnessInputsV12 {
    ah::Digest trace_commit{};
    struct FriLaneV12 {
        uint64_t pow_grind_nonce{0};
        ah::Digest shape_commit{};
        ah::Digest row_root{};
        ah::Digest ood_evaluation_commit{};
        std::vector<ah::Digest> fold_roots;
    };
    std::array<FriLaneV12, kFriLaneCountV12> fri_lane{};
};

struct TranscriptInputsV12 {
    ParentStatementInputsV12 parent_statement{};
    ProofWitnessInputsV12 proof_witness{};
};

struct CallTraceV12 {
    CallSpecV12 spec{};
    std::vector<gf::Fp> values;
    safe::SafeStateSnapshotV12 before{};
    safe::SafeStateSnapshotV12 after{};
};

struct ChannelExecutionV12 {
    ChannelV12 channel{ChannelV12::AirQuotient};
    uint32_t lane{0};
    std::vector<CallTraceV12> calls;
    ah::State final_state{};
    uint64_t permutation_calls{0};
    std::vector<uint32_t> query_indices;
    bool completed{false};
};

struct NativeExecutionV12 {
    ChannelExecutionV12 air_quotient;
    std::array<ChannelExecutionV12, kFriLaneCountV12> fri_lane{};
    bool independent_lane_tags{false};
    bool valid{false};
    std::string note;
};

struct PermutationRowV12 {
    ChannelV12 channel{ChannelV12::AirQuotient};
    uint32_t call_index{0};
    ah::State input{};
    ah::State output{};
    std::vector<gf::Fp3> decomposed_row;
    bool constraints_zero{false};
};

struct AirChannelWitnessV12 {
    ChannelExecutionV12 projected_execution;
    std::vector<PermutationRowV12> permutation_rows;
    bool poseidon_constraints_zero{false};
    bool io_wiring_checked{false};
};

struct AirWitnessV12 {
    AirChannelWitnessV12 air_quotient;
    std::array<AirChannelWitnessV12, kFriLaneCountV12> fri_lane{};
    bool native_differential_equal{false};
    bool lane_order_bound{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool IsMerkleRoleV12(aht::RoleV12 role);
[[nodiscard]] bool IsFiatShamirRoleV12(aht::RoleV12 role);

/** Canonical shape-only program. No proof field is read by this function. */
[[nodiscard]] bool BuildManifestV12(
    const ShapeV12& shape, ManifestV12& out,
    std::string* why = nullptr);

/** Rebuild from shape and compare every domain, role, call and SAFE tag. */
[[nodiscard]] bool ValidateManifestV12(
    const ManifestV12& manifest, std::string* why = nullptr);

/** Exact native execution of the shape-fixed program on canonical inputs. */
[[nodiscard]] bool ExecuteNativeV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    NativeExecutionV12& out, std::string* why = nullptr);

/**
 * Independent AIR-witness projection. Every permutation row is a real
 * stage3_poseidon_air witness and all 472 quadratic identities are evaluated.
 */
[[nodiscard]] bool BuildAirWitnessV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    AirWitnessV12& out, std::string* why = nullptr);

/** Rebuild native and AIR projections and reject any changed witness cell. */
[[nodiscard]] bool ValidateAirWitnessV12(
    const ManifestV12& manifest, const TranscriptInputsV12& inputs,
    const AirWitnessV12& witness, std::string* why = nullptr);

// This slice fixes the program, native semantics and witness interface only.
inline constexpr bool kProofIndependentManifestImplementedV12 = true;
inline constexpr bool kDualQ96TypedDomainsImplementedV12 = true;
inline constexpr bool kNativeAirDifferentialHarnessImplementedV12 = true;
inline constexpr bool kPoseidonPermutationRowsExecutableV12 = true;

inline constexpr bool kProofPayloadMappingCompleteV12 = false;
inline constexpr bool kRecursiveIoWiringConstraintsExecutableV12 = false;
inline constexpr bool kSafeFsRegistryPinnedV12 = false;
inline constexpr bool kDualQ96NiropReductionCertifiedV12 = false;
inline constexpr bool kDualQ96CommonCommitmentHybridCertifiedV12 = false;
inline constexpr bool kSafeFsGlobalReductionCertifiedV12 = false;
inline constexpr bool kSafeFsAuthorityReadyV12 =
    kProofIndependentManifestImplementedV12 &&
    kDualQ96TypedDomainsImplementedV12 &&
    kNativeAirDifferentialHarnessImplementedV12 &&
    kPoseidonPermutationRowsExecutableV12 &&
    kProofPayloadMappingCompleteV12 &&
    kRecursiveIoWiringConstraintsExecutableV12 &&
    kSafeFsRegistryPinnedV12 &&
    kDualQ96NiropReductionCertifiedV12 &&
    kDualQ96CommonCommitmentHybridCertifiedV12 &&
    kSafeFsGlobalReductionCertifiedV12;

static_assert(!kSafeFsAuthorityReadyV12);

} // namespace matmul::v4::rc::stage3_safe_v12_fs_air

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_SAFE_V12_FS_AIR_H
