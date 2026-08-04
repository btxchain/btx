// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_VM_SAME_PARENT_JOIN_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_VM_SAME_PARENT_JOIN_H

#include <matmul/matmul_v4_rc_stage3_constant_width_bytecode_air.h>
#include <matmul/matmul_v4_rc_stage3_registry_membership_air.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace matmul::v4::rc::stage3_registry_vm_same_parent_join {

namespace aq = air_quotient;
namespace cwa = constant_width_bytecode_air;
namespace gf = gkr_field;
namespace registry_air = stage3_registry_membership_air;

inline constexpr uint16_t kRegistryVmSameParentJoinVersionV1 = 1;
inline constexpr uint32_t kRegistryVmDirectAliasesV1 =
    alg_hash::kAlgHashDigestLen +
    registry_air::kRegistryFamilyFieldsV1;

/** Four canonical Goldilocks cells, not eight unconstrained u32 words. */
struct AlgHashCellRefsV1 {
    std::array<uint32_t, alg_hash::kAlgHashDigestLen> limb{};

    bool operator==(const AlgHashCellRefsV1&) const = default;
};

/**
 * The exact 12-field selected registry tuple:
 *
 *   family_index, kind, role, program_hash[4], schema_hash[4], complete.
 */
struct SelectedFamilyCellRefsV1 {
    uint32_t family_index{0};
    uint32_t kind{0};
    uint32_t role{0};
    AlgHashCellRefsV1 program_alg_hash;
    AlgHashCellRefsV1 schema_alg_hash;
    uint32_t semantic_relation_complete{0};

    bool operator==(const SelectedFamilyCellRefsV1&) const = default;
};

/**
 * Typed statement cells consumed by the constant-width child verifier.
 *
 * These must be exact aliases of the registry producer cells returned by
 * CanonicalRegistryProducerRefsV1. A different but equal witness cell is
 * rejected: equality carriers are unnecessary and create a new soundness
 * surface.
 */
struct VmChildStatementCellRefsV1 {
    AlgHashCellRefsV1 registry_alg_root;
    SelectedFamilyCellRefsV1 selected;

    bool operator==(const VmChildStatementCellRefsV1&) const = default;
};

/**
 * Normalized child statement. `quotient` is the executable constant-width
 * verifier statement. The remaining fields are its registry-selected public
 * input ABI; the host verifier currently lacks these fields, so the
 * normalized parent must consume them explicitly.
 */
struct VmChildStatementV1 {
    uint16_t version{kRegistryVmSameParentJoinVersionV1};
    cwa::PublicInputsV1 quotient;
    soundness_scenarios::ProductionProofSiteKind kind{};
    RCStage3RelationRole role{};
    alg_hash::Digest selected_schema_alg_hash{};
    bool semantic_relation_complete{false};
};

[[nodiscard]] VmChildStatementCellRefsV1
CanonicalRegistryProducerRefsV1(
    const registry_air::LayoutV1& layout);

[[nodiscard]] VmChildStatementV1 BuildVmChildStatementV1(
    const registry_air::StatementV1& registry_statement,
    const cwa::PublicInputsV1& quotient);

struct AppendResultV1 {
    bool valid{false};
    bool canonical_registry_uint256_encoding{false};
    bool registry_air_source_constraints_resident{false};
    bool exact_cell_aliases{false};
    bool no_value_or_carrier_columns_added{false};
    bool child_program_id_kind_role_consumes_registry_cells{false};
    bool child_program_alg_hash_consumes_registry_cells{false};
    bool child_schema_alg_hash_consumes_registry_cells{false};
    bool child_semantic_completeness_consumes_registry_cell{false};
    bool child_registry_root_consumes_registry_cells{false};
    bool child_statement_public_constants_constrained{false};
    /**
     * Deliberate residual: this bridge constrains the child statement but
     * does not arithmetize the complete constant-width proof verifier.
     */
    bool complete_vm_child_verifier_same_parent{false};
    bool unified_root_consumes_bridge{false};
    bool production_authority_ready{false};
    uint32_t original_columns{0};
    uint32_t added_columns{0};
    uint32_t added_constraints{0};
    uint64_t violations{0};
    std::string note;
};

/**
 * Append first-row public-statement constraints to the registry AIR parent.
 *
 * No witness or carrier column is allocated. `child_refs` must name exactly
 * the registry digest/selected-claim cells. This makes the producer and
 * consumer the same physical cells rather than relying on host equality.
 */
[[nodiscard]] bool AppendRegistryVmSameParentJoinV1(
    const registry_air::ProductV1& registry_product,
    const VmChildStatementV1& child_statement,
    const VmChildStatementCellRefsV1& child_refs,
    aq::AirConstraintSystem<gf::Fp3>& parent_cs,
    std::vector<std::vector<gf::Fp3>>& parent_columns,
    AppendResultV1& out,
    std::string* why = nullptr);

[[nodiscard]] uint64_t CountViolationsV1(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns);

} // namespace matmul::v4::rc::stage3_registry_vm_same_parent_join

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_REGISTRY_VM_SAME_PARENT_JOIN_H
