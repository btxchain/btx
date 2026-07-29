// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_PHYSICAL_PARENT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_PHYSICAL_PARENT_JOIN_H

#include <matmul/matmul_v4_rc_stage3_air_parent_composer.h>
#include <matmul/matmul_v4_rc_stage3_v13_v14_abi_logup_join.h>
#include <matmul/matmul_v4_rc_stage3_v14_protocol_prefix_join.h>

#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_v13_v14_abi_physical_parent_join {

namespace abi_join = stage3_v13_v14_abi_logup_join;
namespace aq = air_quotient;
namespace composer = stage3_air_parent_composer;
namespace derived = stage3_v13_derived_hash_air;
namespace gf = gkr_field;
namespace occurrence = stage3_v13_occurrence_manifest;
namespace prefix = stage3_v14_protocol_prefix_join;
namespace provenance = stage3_v14_transcript_provenance_join;
namespace tape = stage3_multirow_v13_proof_tape_air;

inline constexpr uint16_t kPhysicalParentJoinVersionV1 = 1;

/**
 * Verifier-rebuilt layout of the actual proof-tape and V14 prefix/provenance
 * constraint systems in one horizontal parent trace.
 *
 * `complete_r0_base_column_indices` contains every resident component column.
 * The ABI LogUp builder appends only its own ordinary decomposition/schedule
 * columns before committing R0 and deriving the two Fp3 challenge lanes.
 */
struct PlanV1 {
    uint16_t version{kPhysicalParentJoinVersionV1};
    uint32_t parent_rows{0};
    uint32_t tape_offset{0};
    uint32_t tape_columns{0};
    uint32_t tape_rows{0};
    uint32_t prefix_offset{0};
    uint32_t prefix_columns{0};
    uint32_t prefix_rows{0};
    uint32_t v14_offset{0};
    uint32_t resident_columns{0};
    composer::ChildAttachmentV1 tape_attachment{};
    composer::ChildAttachmentV1 prefix_attachment{};
    std::vector<uint32_t> complete_r0_base_column_indices;
    abi_join::PlanV1 abi_plan{};
    uint256 plan_root{};
    bool tape_layout_rebuilt{false};
    bool prefix_layout_rebuilt{false};
    bool exact_abi_plan_rebuilt{false};
    bool complete_parent_r0{false};
    bool valid{false};
    std::string note;

};

/**
 * Rebuild the resident parent CS and physical ABI map using public data only.
 * No witness value, host-side decoded byte, or prover-supplied column index is
 * accepted by this function.
 */
[[nodiscard]] bool BuildResidentParentV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    aq::AirConstraintSystem<gf::Fp3>& resident_parent_cs,
    PlanV1& plan,
    std::string* why = nullptr);

/**
 * Challenge-independent physical transcript component.
 *
 * The actual V13 proof-tape verifier, actual V14 prefix/provenance verifier,
 * and the ordinary half of their byte LogUp are all present.  No R0 root or
 * lookup challenge exists yet.  A wider recursive verifier may therefore
 * append this component beside its child-verification relations and derive
 * every dependent challenge from one parent-owned R0.
 */
struct PublicDeterministicComponentV1 {
    uint16_t version{kPhysicalParentJoinVersionV1};
    tape::PublicShapeV1 shape{};
    tape::PublicBindingV1 tape_binding{};
    occurrence::ManifestV1 manifest{};
    alg_hash::Digest transcript_commitment{};
    derived::BindingV1 derived_binding{};
    PlanV1 plan{};
    aq::AirConstraintSystem<gf::Fp3> cs;
    abi_join::EmbeddedBaseV1 abi_base{};
    std::vector<uint32_t> r0_base_column_indices;
    bool actual_verifiers_resident{false};
    bool exact_physical_abi_pre_r0{false};
    bool challenge_columns_absent{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildDeterministicConstraintSystemV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    PublicDeterministicComponentV1& out,
    std::string* why = nullptr);

struct DeterministicComponentV1 {
    PublicDeterministicComponentV1 public_component{};
    std::vector<std::vector<gf::Fp3>> columns;
    uint64_t violations{UINT64_MAX};
    bool actual_tape_witness_resident{false};
    bool actual_v14_prefix_witness_resident{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool BuildDeterministicComponentV1(
    const tape::ProductV1& tape_product,
    const prefix::ProductV1& prefix_product,
    const occurrence::ManifestV1& manifest,
    DeterministicComponentV1& out,
    std::string* why = nullptr);

/**
 * Challenge-dependent suffix after the enclosing parent has committed all
 * ordinary columns.  `component_attachment` must be a literal, non-row-lifted
 * placement of the deterministic component.  The ABI plan is independently
 * rebuilt at the relocated physical column offsets.
 */
struct ComponentFinalizationV1 {
    abi_join::PlanV1 relocated_abi_plan{};
    abi_join::EmbeddedBaseV1 relocated_abi_base{};
    abi_join::EmbeddedFinalizationV1 abi_finalization{};
    bool plan_rebuilt_at_parent_offsets{false};
    bool exact_global_r0_consumed{false};
    bool valid{false};
    std::string note;
};

[[nodiscard]] bool AppendFinalConstraintSystemToParentV1(
    const PublicDeterministicComponentV1& component,
    const composer::ChildAttachmentV1& component_attachment,
    const uint256& domain_separated_public_seed,
    const uint256& global_r0_row_root,
    const std::vector<uint32_t>& global_r0_base_column_indices,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    ComponentFinalizationV1& out,
    std::string* why = nullptr);

[[nodiscard]] bool AppendFinalRelationToParentV1(
    const DeterministicComponentV1& component,
    const composer::ChildAttachmentV1& component_attachment,
    const uint256& domain_separated_public_seed,
    const aq::AirQuotientTwoEpochBaseRowSession& global_r0_session,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    ComponentFinalizationV1& out,
    std::string* why = nullptr);

struct ProductV1 {
    PlanV1 plan{};
    tape::PublicBindingV1 tape_binding{};
    alg_hash::Digest transcript_commitment{};
    derived::BindingV1 derived_binding{};
    aq::AirConstraintSystem<gf::Fp3> resident_parent_cs;
    std::vector<std::vector<gf::Fp3>> resident_parent_columns;
    abi_join::ProductV1 abi_product{};
    uint64_t violations{UINT64_MAX};
    bool actual_tape_verifier_resident{false};
    bool actual_v14_prefix_verifier_resident{false};
    bool actual_tape_cells_referenced{false};
    bool actual_v14_message_cells_referenced{false};
    bool no_host_copied_value_vector{false};
    bool complete_parent_r0_committed{false};
    bool dual_fp3_logup_constrained{false};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    bool valid{false};
    std::string note;
};

/**
 * Materialize the honest parent witness by copying the already-executed tape
 * and V14 prefix products into their canonical resident column ranges, then
 * append the existing dual-Fp3 ABI LogUp directly over those cells.
 */
[[nodiscard]] bool BuildProductV1(
    const tape::ProductV1& tape_product,
    const prefix::ProductV1& prefix_product,
    const occurrence::ManifestV1& manifest,
    const uint256& public_seed,
    ProductV1& out,
    std::string* why = nullptr);

struct ProofV1 {
    uint16_t version{kPhysicalParentJoinVersionV1};
    uint256 plan_root{};
    abi_join::ProofV1 abi_proof{};
    bool recursively_consumed{false};
    bool recursive_authority_ready{false};
    std::string note;
};

[[nodiscard]] bool ProveV1(
    const ProductV1& product,
    const uint256& public_seed,
    ProofV1& out,
    std::string* why = nullptr);

/**
 * Rebuilds both complete resident verifier constraint systems, every physical
 * ABI occurrence and the all-column R0 index before invoking the unmodified
 * Split-RAP verifier.
 */
[[nodiscard]] bool VerifyV1(
    const tape::PublicShapeV1& shape,
    const tape::PublicBindingV1& tape_binding,
    const occurrence::ManifestV1& manifest,
    const alg_hash::Digest& expected_transcript_commitment,
    const derived::BindingV1& expected_derived_binding,
    const uint256& public_seed,
    const ProofV1& proof,
    std::string* why = nullptr);

inline constexpr bool kPhysicalParentJoinExecutableV1 = true;
inline constexpr bool kPhysicalParentJoinRecursiveConsumptionV1 = false;
inline constexpr bool kPhysicalParentJoinAuthorityReadyV1 = false;

static_assert(!kPhysicalParentJoinRecursiveConsumptionV1);
static_assert(!kPhysicalParentJoinAuthorityReadyV1);

} // namespace matmul::v4::rc::stage3_v13_v14_abi_physical_parent_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_V13_V14_ABI_PHYSICAL_PARENT_JOIN_H
