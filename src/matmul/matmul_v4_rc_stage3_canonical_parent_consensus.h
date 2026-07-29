// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_PARENT_CONSENSUS_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_PARENT_CONSENSUS_H

#include <matmul/matmul_v4_rc_stage3_normalized_consensus_binding.h>
#include <matmul/matmul_v4_rc_stage3_normalized_relation_receipt_consumer.h>
#include <matmul/matmul_v4_rc_stage3_universal_two_child_parent.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::canonical_parent_consensus {

namespace aq = air_quotient;
namespace ar = air_recurse;
namespace nav3 = normalized_authority;
namespace ncb = normalized_consensus_binding;
namespace nrrc = normalized_relation_receipt_consumer;
namespace u2 = universal_two_child_parent;

inline constexpr uint16_t kCanonicalParentConsensusVersionV1 = 1;
inline constexpr uint32_t kCanonicalRoleSplitV1 =
    nav3::kRoleCountV3 / 2;

/**
 * Consensus-owned endpoint inventory.
 *
 * Counts and manifest roots are derived from the block dimensions and frozen
 * production schedule before this adapter is called.  They are deliberately
 * separate from the proof-produced relation/semantic/CTL roots.
 */
struct FrozenEndpointScheduleV1 {
    RCStage3RelationEndpoint endpoint{};
    uint64_t instance_count{0};
    uint256 manifest_root{};

    bool operator==(const FrozenEndpointScheduleV1&) const = default;
};

struct FrozenRoleScheduleV1 {
    RCStage3RelationRole role{};
    uint256 program_root{};
    std::vector<FrozenEndpointScheduleV1> endpoints;

    bool operator==(const FrozenRoleScheduleV1&) const = default;
};

/**
 * Canonical public-output ABI of one complete child.
 *
 * `first_trace_column` is the acceptance cell.  It is followed by the role
 * and endpoint fields documented by CanonicalChildPublicOutputCellCountV1,
 * each represented by one canonical u32 base-field cell.  This mapping is
 * selected by the frozen registry, never by a receipt.
 */
struct FrozenChildPublicOutputAbiV1 {
    uint32_t first_trace_column{0};

    bool operator==(const FrozenChildPublicOutputAbiV1&) const = default;
};

/**
 * The consensus-owned inputs which select the exact binary parent.
 *
 * This object is supplied by the executable/frozen protocol registry, never
 * decoded from NAV3.  In particular it contains no parent shape, column list,
 * FixedTrace root, parent-CS commitment, callback or readiness bit.
 */
struct FrozenBinaryParentSpecV1 {
    uint16_t version{kCanonicalParentConsensusVersionV1};
    std::array<u2::PublicShapeV1, 2> child_shape;
    std::array<u2::FrozenRegistryV1, 2> child_registry;
    std::vector<FrozenRoleScheduleV1> role_schedule;
    std::array<FrozenChildPublicOutputAbiV1, 2>
        child_public_output;
};

/**
 * Public statements of the complete child products.
 *
 * The canonical role order is split [0,7) / [7,14).  Each child seed is
 * derived from its exact role-statement half, the block statement, its frozen
 * shape and its frozen relation program.  A caller cannot supply a seed.
 */
struct CompleteChildStatementsV1 {
    uint16_t version{kCanonicalParentConsensusVersionV1};
    std::vector<nav3::RolePinV3> roles;
};

struct RebuiltCanonicalParentV1 {
    uint16_t version{kCanonicalParentConsensusVersionV1};
    u2::HeterogeneousVerifierConstraintSystemV1 verifier;
    nav3::RebuiltVerifierInputsV3 verifier_inputs;
    std::array<uint256, 2> child_statement_root{};
    std::array<uint256, 2> child_fs_seed{};
    bool block_statement_rebuilt{false};
    bool role_inventory_rebuilt{false};
    bool child_seeds_rebuilt{false};
    bool parent_cs_rebuilt{false};
    bool fixed_trace_layout_rebuilt{false};
    bool frozen_occurrence_inventory_enforced{false};
    bool child_public_output_polynomials_constant{false};
    bool child_public_outputs_equality_constrained{false};
    bool receipt_configuration_ignored{false};
    bool authority{false};
    std::string note;
};

/** Exact number of trace cells in one child's canonical public-output ABI. */
[[nodiscard]] uint32_t
CanonicalChildPublicOutputCellCountV1(
    const FrozenBinaryParentSpecV1& frozen,
    uint32_t child);

/**
 * Validate the proof-independent output ABI before building V_CS.
 *
 * Besides canonical role/endpoint order and frozen occurrence equality, this
 * requires every ABI column to have an explicit degree-one transition
 * identity in its frozen child ProgramTable.  Therefore a prover cannot use a
 * nonconstant polynomial which merely agrees with the advertised value at an
 * opened query.
 */
[[nodiscard]] bool ValidateCanonicalChildPublicOutputAbiV1(
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    std::string* why = nullptr);

/**
 * Rebuild the exact parent CS and normalized verifier inputs.
 *
 * `proof_fixed_trace_root` is the one proof commitment admitted by this API.
 * It cannot select the CS, shape, registry, role inventory or column order;
 * the native SAFE FixedTrace verifier subsequently authenticates it.
 */
[[nodiscard]] bool RebuildCanonicalParentV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const uint256& proof_fixed_trace_root,
    RebuiltCanonicalParentV1& out,
    std::string* why = nullptr);

/**
 * Prover-side join point for two complete children.
 *
 * The child proofs are accepted only under the independently derived seeds,
 * frozen ProgramTables and frozen public shapes above.  The returned product
 * can be passed directly to BuildReceiptV1; no receipt-owned configuration is
 * copied into it.
 */
[[nodiscard]] bool BuildCanonicalParentProductV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const std::array<
        aq::AirQuotientProof<
            gkr_field::Fp3,
            ar::AggregateWitness::AlgB3>, 2>& child_proof,
    nrrc::CanonicalRelationParentProductV1& out,
    RebuiltCanonicalParentV1* rebuilt = nullptr,
    std::string* why = nullptr);

/**
 * Consensus-side NAV3 verification.
 *
 * Only the proof's FixedTrace commitment is read before rebuilding.  Every
 * other NAV3 public field is compared to independently reconstructed inputs,
 * then the unmodified native verifier runs.
 */
[[nodiscard]] bool VerifyCanonicalParentReceiptV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const std::vector<unsigned char>& receipt_bytes,
    RebuiltCanonicalParentV1* rebuilt = nullptr,
    std::string* why = nullptr);

inline constexpr bool kCanonicalParentConsensusExecutableV1 = true;
inline constexpr bool kCanonicalParentConsensusAuthorityReadyV1 = false;

static_assert(kCanonicalParentConsensusExecutableV1);
static_assert(!kCanonicalParentConsensusAuthorityReadyV1);

} // namespace matmul::v4::rc::canonical_parent_consensus

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_CANONICAL_PARENT_CONSENSUS_H
