// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/MIT.

#include <matmul/matmul_v4_rc_stage3_canonical_parent_consensus.h>

#include <crypto/common.h>
#include <hash.h>

#include <algorithm>
#include <limits>
#include <string_view>

namespace matmul::v4::rc::canonical_parent_consensus {
namespace gf = gkr_field;
namespace {

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_consensus:" +
            detail;
    }
    return false;
}

bool NonNull(const uint256& value)
{
    return !value.IsNull();
}

bool CanonicalFrozenSchedule(
    const FrozenBinaryParentSpecV1& frozen)
{
    if (frozen.role_schedule.size() !=
            nav3::kRoleCountV3) {
        return false;
    }
    const auto& order = RCStage3UnifiedRoleOrder();
    uint32_t endpoints = 0;
    for (uint32_t role_index = 0;
         role_index < frozen.role_schedule.size();
         ++role_index) {
        const auto& role =
            frozen.role_schedule[role_index];
        if (role.role != order[role_index] ||
            !NonNull(role.program_root)) {
            return false;
        }
        const auto& required =
            RequiredRCStage3RelationEndpoints(role.role);
        if (role.endpoints.size() != required.size()) {
            return false;
        }
        for (size_t endpoint_index = 0;
             endpoint_index < required.size();
             ++endpoint_index) {
            const auto& endpoint =
                role.endpoints[endpoint_index];
            if (endpoint.endpoint !=
                    required[endpoint_index] ||
                endpoint.instance_count == 0 ||
                !NonNull(endpoint.manifest_root)) {
                return false;
            }
        }
        endpoints += role.endpoints.size();
    }
    return endpoints == nav3::kEndpointCountV3;
}

bool CanonicalRoles(
    const FrozenBinaryParentSpecV1& frozen,
    const std::vector<nav3::RolePinV3>& roles)
{
    if (!CanonicalFrozenSchedule(frozen) ||
        roles.size() != nav3::kRoleCountV3) {
        return false;
    }
    uint32_t endpoints = 0;
    for (uint32_t role_index = 0;
         role_index < roles.size(); ++role_index) {
        const auto& role = roles[role_index];
        const auto& schedule =
            frozen.role_schedule[role_index];
        if (role.role != schedule.role ||
            role.program_root != schedule.program_root ||
            !NonNull(role.relation_statement_root) ||
            role.endpoints.size() !=
                schedule.endpoints.size()) {
            return false;
        }
        for (uint32_t endpoint_index = 0;
             endpoint_index < role.endpoints.size();
             ++endpoint_index) {
            const auto& endpoint =
                role.endpoints[endpoint_index];
            const auto& expected =
                schedule.endpoints[endpoint_index];
            if (endpoint.endpoint != expected.endpoint ||
                endpoint.instance_count !=
                    expected.instance_count ||
                endpoint.manifest_root !=
                    expected.manifest_root ||
                !NonNull(endpoint.relation_proof_root) ||
                !NonNull(endpoint.semantic_root) ||
                !NonNull(endpoint.ctl_terminal_root) ||
                !NonNull(
                    endpoint.recursive_child_statement_root)) {
                return false;
            }
        }
        endpoints += role.endpoints.size();
        if (role.endpoint_manifest_root !=
                nav3::ComputeRoleEndpointManifestRootV3(role) ||
            role.role_statement_root !=
                nav3::ComputeRoleStatementRootV3(role)) {
            return false;
        }
    }
    return endpoints == nav3::kEndpointCountV3;
}

constexpr uint32_t kRootU32Cells = 8;
constexpr uint32_t kRoleRootFields = 4;
constexpr uint32_t kEndpointRootFields = 5;

uint32_t ChildRoleBegin(uint32_t child)
{
    return child == 0 ? 0 : kCanonicalRoleSplitV1;
}

uint32_t ChildRoleEnd(uint32_t child)
{
    return child == 0
        ? kCanonicalRoleSplitV1
        : nav3::kRoleCountV3;
}

bool ChildCellCount(
    const FrozenBinaryParentSpecV1& frozen,
    uint32_t child,
    uint32_t& out)
{
    out = 0;
    if (child >= 2 ||
        !CanonicalFrozenSchedule(frozen)) {
        return false;
    }
    uint64_t cells = 1; // exact child acceptance cell
    for (uint32_t role = ChildRoleBegin(child);
         role < ChildRoleEnd(child); ++role) {
        cells += uint64_t{kRoleRootFields} *
            kRootU32Cells;
        cells +=
            frozen.role_schedule[role].endpoints.size() *
            (2U + uint64_t{kEndpointRootFields} *
                        kRootU32Cells);
    }
    if (cells > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    out = static_cast<uint32_t>(cells);
    return true;
}

void AppendRootCells(
    const uint256& root,
    std::vector<gf::Fp3>& cells)
{
    for (uint32_t limb = 0;
        limb < kRootU32Cells; ++limb) {
        cells.push_back(gf::Fp3::FromFp(
            gf::FromU64(
                ReadLE32(root.data() + 4U * limb))));
    }
}

bool ExpectedChildCells(
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& children,
    uint32_t child,
    std::vector<gf::Fp3>& cells)
{
    cells.clear();
    uint32_t expected_count = 0;
    if (!ChildCellCount(
            frozen, child, expected_count) ||
        !CanonicalRoles(frozen, children.roles)) {
        return false;
    }
    cells.reserve(expected_count);
    cells.push_back(gf::Fp3::One());
    for (uint32_t role_index = ChildRoleBegin(child);
         role_index < ChildRoleEnd(child);
         ++role_index) {
        const auto& role = children.roles[role_index];
        AppendRootCells(role.program_root, cells);
        AppendRootCells(
            role.relation_statement_root, cells);
        AppendRootCells(
            role.endpoint_manifest_root, cells);
        AppendRootCells(role.role_statement_root, cells);
        for (const auto& endpoint : role.endpoints) {
            cells.push_back(gf::Fp3::FromFp(
                gf::FromU64(
                    static_cast<uint32_t>(
                        endpoint.instance_count))));
            cells.push_back(gf::Fp3::FromFp(
                gf::FromU64(
                    static_cast<uint32_t>(
                        endpoint.instance_count >> 32))));
            AppendRootCells(
                endpoint.manifest_root, cells);
            AppendRootCells(
                endpoint.relation_proof_root, cells);
            AppendRootCells(
                endpoint.semantic_root, cells);
            AppendRootCells(
                endpoint.ctl_terminal_root, cells);
            AppendRootCells(
                endpoint.recursive_child_statement_root,
                cells);
        }
    }
    return cells.size() == expected_count;
}

ar::ChildPublicInputs ShapeOnlyChild(
    const u2::PublicShapeV1& shape,
    const aq::AirConstraintSystem<gf::Fp3>& cs)
{
    ar::ChildPublicInputs out;
    out.child_n_rows = shape.child_rows;
    out.child_w = shape.child_columns;
    out.child_quotient_len =
        shape.child_quotient_len;
    out.child_n_coeffs = shape.child_coefficients;
    out.child_n_lde = shape.child_lde;
    out.merkle_depth = shape.merkle_depth;
    out.n_folds = shape.folds;
    out.fold_roots.resize(shape.folds);
    out.fold_challenges.assign(
        shape.folds, gf::Fp3::Zero());
    out.column_len = shape.column_lengths;
    out.evals_z1.assign(
        uint64_t{shape.child_columns} + 1U,
        gf::Fp3::Zero());
    out.evals_z2.assign(
        uint64_t{shape.child_columns} + 1U,
        gf::Fp3::Zero());
    out.query_index.assign(shape.queries, 0);
    out.independent_fri_batching =
        shape.independent_fri_batching;
    if (out.independent_fri_batching) {
        out.fri_batch_coefficients.assign(
            uint64_t{shape.child_columns} + 1U,
            gf::Fp3::Zero());
    }
    out.child_constraints = cs.constraints;
    out.ok = true;
    return out;
}

std::vector<bool> ConstantTraceColumns(
    const u2::FrozenRegistryV1& registry,
    uint32_t width)
{
    std::vector<bool> constant(width, false);
    for (const auto& program :
         registry.child_relation_program.programs) {
        if (program.kind !=
                aq::AirKind::kTransition ||
            program.declared_degree != 1 ||
            program.instructions.size() != 3) {
            continue;
        }
        const auto& first = program.instructions[0];
        const auto& second = program.instructions[1];
        const auto& result = program.instructions[2];
        const bool next_current =
            first.opcode ==
                constraint_bytecode::Opcode::Next &&
            second.opcode ==
                constraint_bytecode::Opcode::Current;
        const bool current_next =
            first.opcode ==
                constraint_bytecode::Opcode::Current &&
            second.opcode ==
                constraint_bytecode::Opcode::Next;
        if ((!next_current && !current_next) ||
            first.lhs != second.lhs ||
            first.lhs >= width ||
            first.rhs != 0 || second.rhs != 0 ||
            result.opcode !=
                constraint_bytecode::Opcode::Sub ||
            result.lhs != 0 || result.rhs != 1) {
            continue;
        }
        constant[first.lhs] = true;
    }
    return constant;
}

bool AppendChildPublicOutputBindings(
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& children,
    const std::vector<ar::ChildPublicInputs>& pis,
    u2::HeterogeneousVerifierConstraintSystemV1& verifier,
    std::vector<std::vector<gf::Fp3>>* columns,
    std::string* why)
{
    if (pis.size() != 2 ||
        verifier.parent_cs.n_columns !=
            verifier.fixed_trace.n_columns ||
        (columns != nullptr &&
         columns->size() !=
            verifier.parent_cs.n_columns)) {
        return Fail(why, "public_output_parent_shape");
    }
    for (uint32_t child = 0; child < 2; ++child) {
        std::vector<gf::Fp3> expected;
        if (!ExpectedChildCells(
                frozen, children, child, expected)) {
            return Fail(
                why, "public_output_expected_cells");
        }
        const uint64_t source_end =
            uint64_t{
                frozen.child_public_output[child]
                    .first_trace_column} +
            expected.size();
        if (source_end >
                frozen.child_shape[child]
                    .child_columns) {
            return Fail(
                why, "public_output_child_shape");
        }
        const auto constant =
            ConstantTraceColumns(
                frozen.child_registry[child],
                frozen.child_shape[child]
                    .child_columns);
        for (uint32_t offset = 0;
             offset < expected.size(); ++offset) {
            const uint32_t source =
                frozen.child_public_output[child]
                    .first_trace_column +
                offset;
            if (source >= constant.size() ||
                !constant[source]) {
                return Fail(
                    why,
                    "public_output_not_constant_in_child_air");
            }
        }
        const auto outputs =
            ar::DescribeVerifierAIRParentOutputs(
                pis, child, {});
        std::vector<
            const ar::VerifierAirParentOutput*>
            current(
                frozen.child_shape[child]
                    .child_columns,
                nullptr);
        for (const auto& output : outputs) {
            if (output.kind ==
                    ar::VerifierAirParentOutputKind::
                        CurrentOpening &&
                output.item_index < current.size()) {
                current[output.item_index] = &output;
            }
        }
        for (uint32_t offset = 0;
             offset < expected.size(); ++offset) {
            const uint32_t source =
                frozen.child_public_output[child]
                    .first_trace_column +
                offset;
            if (current[source] == nullptr) {
                return Fail(
                    why, "public_output_vcs_mapping");
            }
            const uint32_t fixed_column =
                verifier.parent_cs.n_columns++;
            verifier.fixed_trace.n_columns =
                verifier.parent_cs.n_columns;
            verifier.fixed_trace.ordered_columns
                .push_back(fixed_column);
            if (columns != nullptr) {
                columns->push_back(
                    std::vector<gf::Fp3>(
                        verifier.parent_cs.n_rows,
                        expected[offset]));
            }

            aq::AirConstraint<gf::Fp3> pin;
            pin.name =
                "canonical_parent.public_output.pin";
            pin.kind = aq::AirKind::kEverywhere;
            pin.alg_degree = 1;
            const gf::Fp3 value = expected[offset];
            pin.eval =
                [fixed_column, value](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Sub(
                        row[fixed_column], value);
                };
            verifier.parent_cs.constraints.push_back(
                std::move(pin));

            aq::AirConstraint<gf::Fp3> equality;
            equality.name =
                "canonical_parent.public_output.child_equality";
            equality.kind = aq::AirKind::kEverywhere;
            equality.alg_degree = 1;
            const auto mapped = *current[source];
            equality.eval =
                [fixed_column, mapped](
                    const std::vector<gf::Fp3>& row,
                    const std::vector<gf::Fp3>&) {
                    return gf::Sub(
                        row[fixed_column],
                        ar::EvaluateVerifierAIRParentOutput(
                            mapped, row));
                };
            verifier.parent_cs.constraints.push_back(
                std::move(equality));
        }
    }
    verifier.callback_schedule_commitment =
        u2::CommitConstraintScheduleV1(
            verifier.parent_cs);
    return true;
}

uint256 ChildStatementRoot(
    const ncb::DirectReceiptConsensusStatementV3& block,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& children,
    uint32_t child)
{
    const uint32_t begin =
        child == 0 ? 0 : kCanonicalRoleSplitV1;
    const uint32_t end =
        child == 0 ? kCanonicalRoleSplitV1
                   : nav3::kRoleCountV3;
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_CHILD_STATEMENT_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << child;
    hash << block.expected_program_registry_root;
    hash << nav3::ComputeDirectOuterStatementRootV3(
        block.public_statement, children.roles);
    hash << u2::CommitPublicShapeV1(
        frozen.child_shape[child]);
    hash << frozen.child_registry[child].program_root;
    hash << begin << end;
    for (uint32_t role = begin; role < end; ++role) {
        hash << children.roles[role].role_statement_root;
    }
    return hash.GetHash();
}

uint256 ChildFsSeed(
    const uint256& child_statement_root,
    uint32_t child)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_CHILD_FS_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << child;
    hash << child_statement_root;
    return hash.GetHash();
}

uint256 HashTopology(
    const u2::HeterogeneousVerifierConstraintSystemV1& verifier)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_TOPOLOGY_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << verifier.arity;
    hash << kCanonicalRoleSplitV1;
    hash << verifier.binary_statement_commitment;
    for (uint32_t child = 0; child < 2; ++child) {
        hash << verifier.shape_commitment[child];
        hash << verifier.registry_program_root[child];
    }
    return hash.GetHash();
}

uint256 HashAggregationSchedule(
    const u2::HeterogeneousVerifierConstraintSystemV1& verifier)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_SCHEDULE_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << verifier.callback_schedule_commitment;
    hash << verifier.fixed_trace.version;
    hash << verifier.fixed_trace.arity;
    hash << verifier.fixed_trace.n_rows;
    hash << verifier.fixed_trace.n_columns;
    hash << static_cast<uint64_t>(
        verifier.fixed_trace.ordered_columns.size());
    for (uint32_t column :
         verifier.fixed_trace.ordered_columns) {
        hash << column;
    }
    return hash.GetHash();
}

uint256 HashOccurrenceManifest(
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& children)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_OCCURRENCES_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << nav3::ComputeRoleManifestRootV3(children.roles);
    for (const auto& role : frozen.role_schedule) {
        hash << static_cast<uint16_t>(role.role);
        hash << role.program_root;
        for (const auto& endpoint : role.endpoints) {
            hash << static_cast<uint16_t>(
                endpoint.endpoint);
            hash << endpoint.instance_count;
            hash << endpoint.manifest_root;
        }
    }
    return hash.GetHash();
}

uint256 HashVerifierProgram(
    const u2::HeterogeneousVerifierConstraintSystemV1& verifier)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_VERIFIER_PROGRAM_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << verifier.registry_program_root[0];
    hash << verifier.registry_program_root[1];
    hash << verifier.callback_schedule_commitment;
    return hash.GetHash();
}

uint256 HashAbiPlan(
    const u2::HeterogeneousVerifierConstraintSystemV1& verifier)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_ABI_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << verifier.fixed_trace.n_rows;
    hash << verifier.fixed_trace.n_witness_columns;
    hash << verifier.fixed_trace.n_columns;
    for (uint32_t child = 0; child < 2; ++child) {
        const auto& fixed =
            verifier.fixed_trace.children[child];
        hash << fixed.query_index;
        hash << fixed.air_lambda;
        hash << fixed.fri_lambda;
        hash << fixed.z1 << fixed.z2;
        hash << fixed.w1 << fixed.w2;
        hash << fixed.final_value;
    }
    return hash.GetHash();
}

uint256 HashSelectionPlan(
    const std::array<uint256, 2>& child_statement_root,
    const std::array<uint256, 2>& child_fs_seed)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_SELECTION_V1";
    hash << kCanonicalParentConsensusVersionV1;
    for (uint32_t child = 0; child < 2; ++child) {
        hash << child;
        hash << child_statement_root[child];
        hash << child_fs_seed[child];
    }
    return hash.GetHash();
}

uint256 HashDerivedPlan(
    const u2::HeterogeneousVerifierConstraintSystemV1& verifier)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_DERIVATIONS_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << verifier.callback_schedule_commitment;
    hash << static_cast<uint64_t>(
        verifier.parent_cs.constraints.size());
    for (const auto& constraint :
         verifier.parent_cs.constraints) {
        hash << std::string{constraint.name};
        hash << static_cast<uint8_t>(constraint.kind);
        hash << constraint.alg_degree;
    }
    return hash.GetHash();
}

uint256 HashParentNode(
    const std::array<uint256, 2>& child_statement_root,
    const uint256& topology,
    const uint256& schedule)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_NODE_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << child_statement_root[0];
    hash << child_statement_root[1];
    hash << topology;
    hash << schedule;
    return hash.GetHash();
}

uint256 HashParentContext(
    const uint256& outer,
    const uint256& node)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_CANONICAL_PARENT_CONTEXT_V1";
    hash << kCanonicalParentConsensusVersionV1;
    hash << outer;
    hash << node;
    return hash.GetHash();
}

bool SameConstraintDescriptors(
    const aq::AirConstraintSystem<gkr_field::Fp3>& lhs,
    const aq::AirConstraintSystem<gkr_field::Fp3>& rhs)
{
    if (lhs.n_rows != rhs.n_rows ||
        lhs.n_columns != rhs.n_columns ||
        lhs.preprocessed_pin_ood !=
            rhs.preprocessed_pin_ood ||
        lhs.constraints.size() !=
            rhs.constraints.size() ||
        u2::CommitConstraintScheduleV1(lhs) !=
            u2::CommitConstraintScheduleV1(rhs)) {
        return false;
    }
    for (size_t index = 0;
         index < lhs.constraints.size(); ++index) {
        if (std::string_view{lhs.constraints[index].name} !=
                std::string_view{rhs.constraints[index].name} ||
            lhs.constraints[index].kind !=
                rhs.constraints[index].kind ||
            lhs.constraints[index].alg_degree !=
                rhs.constraints[index].alg_degree) {
            return false;
        }
    }
    return true;
}

} // namespace

uint32_t CanonicalChildPublicOutputCellCountV1(
    const FrozenBinaryParentSpecV1& frozen,
    uint32_t child)
{
    uint32_t cells = 0;
    return ChildCellCount(frozen, child, cells)
        ? cells
        : 0;
}

bool ValidateCanonicalChildPublicOutputAbiV1(
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    std::string* why)
{
    if (!CanonicalRoles(
            frozen, complete_children.roles)) {
        return Fail(why, "complete_child_roles");
    }
    for (uint32_t child = 0; child < 2; ++child) {
        uint32_t cells = 0;
        if (!ChildCellCount(frozen, child, cells) ||
            cells == 0) {
            return Fail(
                why, "public_output_cell_count");
        }
        const uint64_t end =
            uint64_t{
                frozen.child_public_output[child]
                    .first_trace_column} +
            cells;
        if (end >
                frozen.child_shape[child]
                    .child_columns) {
            return Fail(
                why, "public_output_child_shape");
        }
        const auto constant =
            ConstantTraceColumns(
                frozen.child_registry[child],
                frozen.child_shape[child]
                    .child_columns);
        for (uint32_t offset = 0;
             offset < cells; ++offset) {
            const uint32_t source =
                frozen.child_public_output[child]
                    .first_trace_column +
                offset;
            if (source >= constant.size() ||
                !constant[source]) {
                return Fail(
                    why,
                    "public_output_not_constant_in_child_air");
            }
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_consensus:"
            "frozen_child_public_output_abi_valid";
    }
    return true;
}

bool RebuildCanonicalParentV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const uint256& proof_fixed_trace_root,
    RebuiltCanonicalParentV1& out,
    std::string* why)
{
    out = {};
    if (frozen.version !=
            kCanonicalParentConsensusVersionV1 ||
        complete_children.version !=
            kCanonicalParentConsensusVersionV1 ||
        block_statement.outer_binding_kind !=
            nav3::OuterBindingKindV3::DirectBlockReceipt ||
        block_statement.expected_program_registry_root.IsNull() ||
        block_statement.expected_program_registry_root !=
            block_statement.public_statement
                .program_consensus_pin
                .recursive_alg_hash_root ||
        proof_fixed_trace_root.IsNull()) {
        return Fail(why, "public_prefix");
    }
    if (!ValidateCanonicalChildPublicOutputAbiV1(
            frozen, complete_children, why)) {
        return false;
    }
    if (!u2::BuildHeterogeneousVerifierConstraintSystemV1(
            frozen.child_shape,
            frozen.child_registry,
            out.verifier, why)) {
        out = {};
        return false;
    }
    if (!out.verifier.proof_tape_independent ||
        out.verifier.authority) {
        out = {};
        return Fail(why, "verifier_rebuild");
    }
    std::vector<ar::ChildPublicInputs> shape_only;
    shape_only.reserve(2);
    for (uint32_t child = 0; child < 2; ++child) {
        shape_only.push_back(ShapeOnlyChild(
            frozen.child_shape[child],
            out.verifier.child_cs[child]));
    }
    if (!AppendChildPublicOutputBindings(
            frozen, complete_children, shape_only,
            out.verifier, nullptr, why)) {
        out = {};
        return false;
    }
    for (uint32_t child = 0; child < 2; ++child) {
        out.child_statement_root[child] =
            ChildStatementRoot(
                block_statement, frozen,
                complete_children, child);
        out.child_fs_seed[child] =
            ChildFsSeed(
                out.child_statement_root[child],
                child);
        if (out.child_statement_root[child].IsNull() ||
            out.child_fs_seed[child].IsNull()) {
            out = {};
            return Fail(why, "child_statement_seed");
        }
    }

    nav3::ParentShapeV3 parent_shape;
    if (!nrrc::DeriveParentShapeV1(
            out.verifier.parent_cs,
            parent_shape, why)) {
        out = {};
        return false;
    }
    nav3::RebuiltVerifierInputsV3 inputs;
    inputs.outer_binding_kind =
        nav3::OuterBindingKindV3::DirectBlockReceipt;
    inputs.public_statement =
        block_statement.public_statement;
    inputs.outer_statement_root =
        nav3::ComputeDirectOuterStatementRootV3(
            block_statement.public_statement,
            complete_children.roles);
    inputs.program_registry_root =
        block_statement.expected_program_registry_root;
    inputs.topology_manifest_root =
        HashTopology(out.verifier);
    inputs.aggregation_schedule_root =
        HashAggregationSchedule(out.verifier);
    inputs.occurrence_manifest_root =
        HashOccurrenceManifest(
            frozen, complete_children);
    inputs.verifier_program_root =
        HashVerifierProgram(out.verifier);
    inputs.abi_plan_root =
        HashAbiPlan(out.verifier);
    inputs.selection_plan_root =
        HashSelectionPlan(
            out.child_statement_root,
            out.child_fs_seed);
    inputs.derived_hash_plan_root =
        HashDerivedPlan(out.verifier);
    inputs.fixed_trace_columns =
        out.verifier.fixed_trace.ordered_columns;
    inputs.fixed_trace_row_root =
        proof_fixed_trace_root;
    inputs.roles = complete_children.roles;
    inputs.parent_shape = parent_shape;
    inputs.parent_node_binding =
        HashParentNode(
            out.child_statement_root,
            inputs.topology_manifest_root,
            inputs.aggregation_schedule_root);
    inputs.parent_context_binding =
        HashParentContext(
            inputs.outer_statement_root,
            inputs.parent_node_binding);
    inputs.parent_program_root =
        inputs.verifier_program_root;
    inputs.parent_cs_commitment =
        out.verifier.callback_schedule_commitment;

    if (inputs.outer_statement_root.IsNull() ||
        inputs.fixed_trace_columns.empty() ||
        inputs.fixed_trace_columns.size() >=
            inputs.parent_shape.proof_columns ||
        inputs.parent_cs_commitment !=
            u2::CommitConstraintScheduleV1(
                out.verifier.parent_cs)) {
        out = {};
        return Fail(why, "rebuilt_inputs");
    }
    out.verifier_inputs = std::move(inputs);
    out.block_statement_rebuilt = true;
    out.role_inventory_rebuilt = true;
    out.child_seeds_rebuilt = true;
    out.parent_cs_rebuilt = true;
    out.fixed_trace_layout_rebuilt = true;
    out.frozen_occurrence_inventory_enforced = true;
    out.child_public_output_polynomials_constant = true;
    out.child_public_outputs_equality_constrained = true;
    out.receipt_configuration_ignored = true;
    out.authority = false;
    out.note =
        "stage3:canonical_parent_consensus:"
        "parent_and_nav3_inputs_rebuilt;"
        "frozen_occurrences_enforced;"
        "child_public_output_polynomials_constant;"
        "child_public_outputs_equality_constrained;"
        "authority_waits_for_complete_same_parent_child_acceptance";
    if (why != nullptr) *why = out.note;
    return true;
}

bool BuildCanonicalParentProductV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const std::array<
        aq::AirQuotientProof<
            gkr_field::Fp3,
            ar::AggregateWitness::AlgB3>, 2>& child_proof,
    nrrc::CanonicalRelationParentProductV1& out,
    RebuiltCanonicalParentV1* rebuilt_out,
    std::string* why)
{
    out = {};
    RebuiltCanonicalParentV1 seed_rebuild;
    // A non-null local placeholder is sufficient here: neither the parent CS
    // nor any derived child seed depends on the proof commitment.
    HashWriter placeholder_hash;
    placeholder_hash <<
        "BTX_RC_STAGE3_CANONICAL_PARENT_R0_PLACEHOLDER_V1";
    const uint256 placeholder =
        placeholder_hash.GetHash();
    if (!RebuildCanonicalParentV1(
            block_statement, frozen,
            complete_children, placeholder,
            seed_rebuild, why)) {
        return false;
    }

    ar::VerifierAirFixedTraceLayoutV1 layout;
    auto witness =
        ar::BuildAggregateWitnessHeterogeneousFixedTraceV1(
            {seed_rebuild.verifier.child_cs[0],
             seed_rebuild.verifier.child_cs[1]},
            {child_proof[0], child_proof[1]},
            {seed_rebuild.child_fs_seed[0],
             seed_rebuild.child_fs_seed[1]},
            layout, {});
    if (!witness.ok) {
        return Fail(why, "complete_child_join_build");
    }
    u2::HeterogeneousVerifierConstraintSystemV1
        materialized;
    materialized.shape = frozen.child_shape;
    materialized.parent_cs = std::move(witness.cs);
    materialized.fixed_trace = layout;
    if (!AppendChildPublicOutputBindings(
            frozen, complete_children, witness.pis,
            materialized, &witness.columns, why)) {
        return false;
    }
    witness.cs = std::move(materialized.parent_cs);
    layout = std::move(materialized.fixed_trace);
    if (!witness.ok ||
        !SameConstraintDescriptors(
            witness.cs,
            seed_rebuild.verifier.parent_cs) ||
        layout.ordered_columns !=
            seed_rebuild.verifier.fixed_trace
                .ordered_columns ||
        ar::CountWitnessViolationsOnH(
            witness.cs, witness.columns) != 0) {
        return Fail(why, "complete_child_join");
    }
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            witness.cs, witness.columns,
            layout.ordered_columns);
    if (!r0.valid ||
        r0.base_row_commitment.IsNull()) {
        return Fail(why, "parent_r0");
    }

    RebuiltCanonicalParentV1 final_rebuild;
    if (!RebuildCanonicalParentV1(
            block_statement, frozen,
            complete_children,
            r0.base_row_commitment,
            final_rebuild, why) ||
        !SameConstraintDescriptors(
            witness.cs,
            final_rebuild.verifier.parent_cs) ||
        final_rebuild.child_fs_seed !=
            seed_rebuild.child_fs_seed) {
        return Fail(why, "final_rebuild");
    }

    out.version =
        nrrc::kNormalizedRelationReceiptConsumerVersionV1;
    out.cs = witness.cs;
    out.columns = witness.columns;
    out.r0_base_column_indices =
        layout.ordered_columns;
    out.r0_session = r0;
    out.verifier_inputs =
        final_rebuild.verifier_inputs;
    if (rebuilt_out != nullptr) {
        *rebuilt_out = final_rebuild;
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_consensus:"
            "complete_children_joined";
    }
    return true;
}

bool VerifyCanonicalParentReceiptV1(
    const ncb::DirectReceiptConsensusStatementV3& block_statement,
    const FrozenBinaryParentSpecV1& frozen,
    const CompleteChildStatementsV1& complete_children,
    const std::vector<unsigned char>& receipt_bytes,
    RebuiltCanonicalParentV1* rebuilt_out,
    std::string* why)
{
    std::string decode_why;
    const auto receipt =
        nav3::DeserializeNormalizedAuthorityReceiptV3(
            receipt_bytes, &decode_why);
    if (!receipt.has_value()) {
        return Fail(
            why, "receipt_decode:" + decode_why);
    }
    RebuiltCanonicalParentV1 rebuilt;
    if (!RebuildCanonicalParentV1(
            block_statement, frozen,
            complete_children,
            receipt->fixed_trace_row_root,
            rebuilt, why)) {
        return false;
    }
    if (!nrrc::VerifyReceiptV1(
            rebuilt.verifier.parent_cs,
            rebuilt.verifier_inputs,
            receipt_bytes, nullptr, why)) {
        return false;
    }
    if (rebuilt_out != nullptr) {
        *rebuilt_out = std::move(rebuilt);
    }
    if (why != nullptr) {
        *why =
            "stage3:canonical_parent_consensus:"
            "receipt_verified_from_block_and_frozen_parent";
    }
    return true;
}

} // namespace matmul::v4::rc::canonical_parent_consensus
