// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_relation_local_sharding.h>

#include <hash.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <limits>
#include <map>
#include <set>
#include <utility>

namespace matmul::v4::rc::stage3_relation_local_sharding {
namespace {

namespace cb = constraint_bytecode;
namespace gf = gkr_field;

bool Fail(std::string* why, const char* suffix)
{
    if (why != nullptr) {
        *why =
            std::string{"stage3:relation_local_sharding:"} +
            suffix;
    }
    return false;
}

bool IsPowerOfTwo(uint32_t value)
{
    return value >= 2 &&
        (value & (value - 1)) == 0;
}

template <typename T>
void SortUnique(std::vector<T>& values)
{
    std::sort(values.begin(), values.end());
    values.erase(
        std::unique(values.begin(), values.end()),
        values.end());
}

std::vector<uint32_t> UnionColumns(
    const std::vector<uint32_t>& lhs,
    const std::vector<uint32_t>& rhs)
{
    std::vector<uint32_t> out;
    out.reserve(lhs.size() + rhs.size());
    std::set_union(
        lhs.begin(), lhs.end(),
        rhs.begin(), rhs.end(),
        std::back_inserter(out));
    return out;
}

uint32_t IntersectionSize(
    const std::vector<uint32_t>& lhs,
    const std::vector<uint32_t>& rhs)
{
    uint32_t count = 0;
    auto a = lhs.begin();
    auto b = rhs.begin();
    while (a != lhs.end() && b != rhs.end()) {
        if (*a < *b) {
            ++a;
        } else if (*b < *a) {
            ++b;
        } else {
            ++count;
            ++a;
            ++b;
        }
    }
    return count;
}

ConstraintSupportV1 BuildSupport(
    const cb::Program& program)
{
    ConstraintSupportV1 out;
    out.ordinal = program.constraint_ordinal;
    out.program_commitment =
        cb::CommitProgram(program);
    out.kind = program.kind;
    out.declared_degree = program.declared_degree;
    for (const auto& instruction :
         program.instructions) {
        if (instruction.opcode == cb::Opcode::Current) {
            out.current_columns.push_back(
                instruction.lhs);
            out.global_columns.push_back(
                instruction.lhs);
        } else if (
            instruction.opcode == cb::Opcode::Next) {
            out.next_columns.push_back(
                instruction.lhs);
            out.global_columns.push_back(
                instruction.lhs);
        }
    }
    SortUnique(out.current_columns);
    SortUnique(out.next_columns);
    SortUnique(out.global_columns);
    return out;
}

bool ProjectProgram(
    const cb::Program& original,
    const std::vector<uint32_t>& global_columns,
    uint32_t local_ordinal,
    cb::Program& out)
{
    out = original;
    out.constraint_ordinal = local_ordinal;
    out.current_width =
        static_cast<uint32_t>(
            global_columns.size());
    out.next_width = out.current_width;
    for (auto& instruction : out.instructions) {
        if (instruction.opcode != cb::Opcode::Current &&
            instruction.opcode != cb::Opcode::Next) {
            continue;
        }
        const auto it = std::lower_bound(
            global_columns.begin(),
            global_columns.end(),
            instruction.lhs);
        if (it == global_columns.end() ||
            *it != instruction.lhs) {
            return false;
        }
        instruction.lhs =
            static_cast<uint32_t>(
                it - global_columns.begin());
    }
    return cb::ValidateProgram(out);
}

uint32_t LocalColumn(
    const std::vector<uint32_t>& columns,
    uint32_t global)
{
    const auto it = std::lower_bound(
        columns.begin(), columns.end(), global);
    if (it == columns.end() || *it != global) {
        return std::numeric_limits<uint32_t>::max();
    }
    return static_cast<uint32_t>(
        it - columns.begin());
}

uint256 CommitManifest(
    const RelationLocalShardManifestV1& manifest)
{
    if (manifest.shards.empty() ||
        manifest.original_program_table_commitment.IsNull()) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_RELATION_LOCAL_SHARD_MANIFEST_V1";
    hash << manifest.version;
    hash << static_cast<uint16_t>(manifest.role);
    hash << manifest.trace_rows;
    hash << manifest.original_columns;
    hash << manifest.original_constraints;
    hash << manifest.maximum_shard_columns;
    hash << manifest.original_program_table_commitment;
    hash << static_cast<uint32_t>(
        manifest.supports.size());
    for (const auto& support : manifest.supports) {
        hash << support.ordinal;
        hash << support.program_commitment;
        hash << static_cast<uint8_t>(support.kind);
        hash << support.declared_degree;
        hash << support.global_columns;
        hash << support.current_columns;
        hash << support.next_columns;
    }
    hash << static_cast<uint32_t>(
        manifest.shards.size());
    for (const auto& shard : manifest.shards) {
        hash << shard.index;
        hash << shard.global_columns;
        hash << shard.constraint_ordinals;
        hash << shard.projected_table_commitment;
    }
    hash << static_cast<uint32_t>(
        manifest.equality_links.size());
    for (const auto& link : manifest.equality_links) {
        hash << link.index;
        hash << link.global_column;
        hash << link.anchor_shard;
        hash << link.replica_shard;
        hash << link.anchor_local_column;
        hash << link.replica_local_column;
        hash << link.tuple_arity;
        hash << link.independent_lanes;
        hash << link.row_index_tagged;
        hash <<
            link.challenges_after_all_shard_commitments;
        hash << link.discharged_by_shared_global_root;
    }
    hash << static_cast<uint32_t>(
        manifest.aggregation_levels.size());
    for (const auto& level :
         manifest.aggregation_levels) {
        hash << level.level;
        hash << level.input_receipts;
        hash << level.parent_receipts;
    }
    return hash.GetHash();
}

bool CheckedCost(
    RelationLocalCostModelV1& cost,
    const std::vector<RelationLocalShardV1>& shards)
{
    __uint128_t cells = 0;
    __uint128_t openings = 0;
    for (const auto& shard : shards) {
        cells +=
            __uint128_t{shard.global_columns.size()} *
            cost.trace_rows;
        openings +=
            __uint128_t{
                shard.global_columns.size() + 1} *
            kRelationLocalShardQueriesV1 * 2 *
            kRelationLocalFp3BytesV1;
    }
    if (cells >
            std::numeric_limits<uint64_t>::max() ||
        openings >
            std::numeric_limits<uint64_t>::max() ||
        cells * kRelationLocalFp3BytesV1 >
            std::numeric_limits<uint64_t>::max()) {
        return false;
    }
    cost.sharded_trace_cells =
        static_cast<uint64_t>(cells);
    cost.sharded_trace_bytes =
        static_cast<uint64_t>(
            cells * kRelationLocalFp3BytesV1);
    cost.direct_opening_value_bytes_lower_bound =
        static_cast<uint64_t>(openings);
    return true;
}

std::pair<uint32_t, uint32_t>
ArityFourCounts(uint32_t leaves)
{
    uint32_t nodes = 0;
    uint32_t levels = 0;
    while (leaves > 1) {
        leaves =
            (leaves +
             kRelationLocalShardRecursionArityV1 - 1) /
            kRelationLocalShardRecursionArityV1;
        if (nodes >
            std::numeric_limits<uint32_t>::max() -
                leaves) {
            return {
                std::numeric_limits<uint32_t>::max(),
                std::numeric_limits<uint32_t>::max()};
        }
        nodes += leaves;
        ++levels;
    }
    return {nodes, levels};
}

uint32_t CeilLog2(uint32_t value)
{
    uint32_t bits = 0;
    uint32_t power = 1;
    while (power < value) {
        power <<= 1;
        ++bits;
    }
    return bits;
}

using Audit = CurrentRelationLocalProductionAuditV1;

struct CanonicalTableSpec {
    const char* family;
    uint16_t mapped_endpoint;
    cb::ProgramTable table;
    const char* residual;
    bool semantic_endpoint_complete;
};

struct RoleEndpointInterval {
    RCStage3RelationRole role;
    uint16_t first;
    uint16_t count;
};

constexpr std::array<RoleEndpointInterval, 14>
    ROLE_ENDPOINT_INTERVALS{{
        {RCStage3RelationRole::EpisodeDeterministicBuilder, 1, 4},
        {RCStage3RelationRole::EpisodeGemm, 5, 5},
        {RCStage3RelationRole::EpisodeExtract, 10, 5},
        {RCStage3RelationRole::EpisodeWiring, 15, 4},
        {RCStage3RelationRole::EpisodeTileTree, 19, 4},
        {RCStage3RelationRole::EpisodeDigest, 23, 4},
        {RCStage3RelationRole::CoupledBank, 27, 3},
        {RCStage3RelationRole::CoupledGemm, 30, 4},
        {RCStage3RelationRole::CoupledExchange, 34, 3},
        {RCStage3RelationRole::CoupledPermutation, 37, 2},
        {RCStage3RelationRole::CoupledMix, 39, 3},
        {RCStage3RelationRole::CoupledExtract, 42, 5},
        {RCStage3RelationRole::CoupledBarrier, 47, 3},
        {RCStage3RelationRole::CoupledDigest, 50, 3},
    }};

bool AppendCanonicalTable(
    std::vector<CanonicalTableSpec>& out,
    const char* family,
    uint16_t mapped_endpoint,
    cb::ProgramTable table,
    const char* residual,
    bool semantic_endpoint_complete)
{
    if (!cb::ValidateProgramTable(table) ||
        cb::CommitProgramTable(table).IsNull()) {
        return false;
    }
    out.push_back({
        family, mapped_endpoint, std::move(table), residual,
        semantic_endpoint_complete});
    return true;
}

std::vector<CanonicalTableSpec>
BuildCurrentCanonicalTableSpecs(bool& ok)
{
    std::vector<CanonicalTableSpec> out;
    ok = true;
    auto add = [&](const char* family,
                   uint16_t endpoint,
                   cb::ProgramTable table,
                   const char* residual,
                   bool semantic_endpoint_complete = false) {
        ok = AppendCanonicalTable(
                 out, family, endpoint,
                 std::move(table), residual,
                 semantic_endpoint_complete) &&
            ok;
    };

    for (const auto family : {
             RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
             RCStage3EpisodeAirFamily::WiringEqualityFp3V1}) {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeLocalKernelProgramTable(
                family, table) &&
            ok;
        if (table.programs.empty()) continue;
        if (family ==
            RCStage3EpisodeAirFamily::GemmEndpointFp3V1) {
            add("episode.gemm.endpoint", 7, std::move(table),
                "operand_openings,sumcheck,range,and_all_layer_schedule");
        } else {
            add("episode.wiring.equality", 15, std::move(table),
                "transpose,residual,round_order,and_full_copy_schedule");
        }
    }
    for (const auto role : {
             RCStage3RelationRole::CoupledBank,
             RCStage3RelationRole::CoupledGemm,
             RCStage3RelationRole::CoupledExchange,
             RCStage3RelationRole::CoupledPermutation,
             RCStage3RelationRole::CoupledMix}) {
        cb::ProgramTable table;
        ok =
            BuildRCStage3CoupledLocalKernelProgramTable(
                role, table) &&
            ok;
        if (table.programs.empty()) continue;
        switch (role) {
        case RCStage3RelationRole::CoupledBank:
            add("coupled.bank.local_kernel", 28, std::move(table),
                "seed_xof,page_inclusion,and_bank_root_hash");
            break;
        case RCStage3RelationRole::CoupledGemm:
            add("coupled.gemm.local_kernel", 32, std::move(table),
                "operand_openings,full_manifest,and_signed_range");
            break;
        case RCStage3RelationRole::CoupledExchange:
            add("coupled.exchange.local_kernel", 36, std::move(table),
                "hash_xof,schedule,and_material_exchange");
            break;
        case RCStage3RelationRole::CoupledPermutation:
            add("coupled.permutation.local_kernel", 38, std::move(table),
                "bit_affine_schedule_and_global_permutation");
            break;
        case RCStage3RelationRole::CoupledMix:
            add("coupled.mix.local_kernel", 40, std::move(table),
                "global_mix_schedule_and_endpoint_provenance");
            break;
        default:
            ok = false;
            break;
        }
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeBuilderTraceProgramTable(table) &&
            ok;
        add("episode.builder.dequant", 4, std::move(table),
            "header_params,seed_chain,operand_xof,and_full_trace_binding");
    }
    for (const auto role : {
             RCStage3RelationRole::EpisodeExtract,
             RCStage3RelationRole::CoupledExtract}) {
        cb::ProgramTable table;
        ok =
            BuildRCStage3ExtractMixProgramTable(role, table) &&
            ok;
        add(role == RCStage3RelationRole::EpisodeExtract
                ? "episode.extract.local_mix"
                : "coupled.extract.local_mix",
            role == RCStage3RelationRole::EpisodeExtract ? 11 : 43,
            std::move(table),
            "all_tile_schedule,chacha,scale_hash,range,and_output_binding");
    }
    for (const auto role : {
             RCStage3RelationRole::EpisodeDigest,
             RCStage3RelationRole::CoupledBarrier,
             RCStage3RelationRole::CoupledDigest}) {
        cb::ProgramTable table;
        ok =
            BuildRCStage3RootChainVectorProgramTable(
                role, table) &&
            ok;
        switch (role) {
        case RCStage3RelationRole::EpisodeDigest:
            add("episode.digest.root_vector", 24, std::move(table),
                "round_root_hash,episode_sha256d,and_pow_binding");
            break;
        case RCStage3RelationRole::CoupledBarrier:
            add("coupled.barrier.root_vector", 49, std::move(table),
                "barrier_input_provenance_and_sha256d");
            break;
        case RCStage3RelationRole::CoupledDigest:
            add("coupled.digest.root_vector", 52, std::move(table),
                "bank_barrier_provenance_and_final_sha256d");
            break;
        default:
            ok = false;
            break;
        }
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeDigestPreimageByteBridgeProgramTable(
                table) &&
            ok;
        add("episode.digest.preimage_byte_bridge", 24,
            std::move(table),
            "endpoint23_tile_root_ancestry;"
            "normalized_recursive_consumption");
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeTileTreeByteBridgeProgramTable(
                table) &&
            ok;
        add("episode.tile_tree.signed_byte_bridge", 20,
            std::move(table),
            "leaf_internal_root_hash_output_ctl;"
            "normalized_recursive_consumption");
    }
    for (const auto role : {
             RCStage3RelationRole::
                 EpisodeDeterministicBuilder,
             RCStage3RelationRole::EpisodeGemm,
             RCStage3RelationRole::EpisodeExtract,
             RCStage3RelationRole::EpisodeWiring,
             RCStage3RelationRole::EpisodeTileTree,
             RCStage3RelationRole::EpisodeDigest}) {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeSemanticMemoryProgramTable(
                role, table) &&
            ok;
        const bool builder_params =
            role == RCStage3RelationRole::
                EpisodeDeterministicBuilder;
        const bool header_target =
            role == RCStage3RelationRole::EpisodeDigest;
        add("episode.semantic_memory",
            builder_params ? 1 : (header_target ? 25 : 0),
            std::move(table),
            builder_params
                ? "semantic_relation_complete;"
                  "normalized_recursive_consumption_remains"
                : (header_target
                       ? "semantic_relation_complete;"
                         "normalized_recursive_consumption_remains"
                       : "generic_value_export_alias_only;"
                         "endpoint_relation_still_required"),
            builder_params || header_target);
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodeHeaderTargetEqualityProgramTable(
                table) &&
            ok;
        add("episode.digest.header_target", 25, std::move(table),
            "semantic_relation_complete;"
            "normalized_recursive_consumption_remains",
            true);
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3EpisodePowProgramTable(table) &&
            ok;
        add("episode.digest.pow_borrow_chain", 26,
            std::move(table),
            "episode_digest_producer_equality;"
            "normalized_recursive_consumption");
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3CoupledBankDequantProgramTableCanonical(
                table) &&
            ok;
        add("coupled.bank.dequant", 28, std::move(table),
            "seed_xof,page_inclusion,and_endpoint28_to_29_hash_bridge");
    }
    {
        cb::ProgramTable table;
        ok =
            BuildRCStage3CoupledBankByteBridgeProgramTable(
                table) &&
            ok;
        add("coupled.bank.signed_byte_bridge", 28,
            std::move(table),
            "normalized_split_rap_child_consumption;"
            "upstream_seed_xof_recursive_provenance");
    }
    return out;
}

bool PopulateRoleSupportTopology(
    const std::vector<CanonicalTableSpec>& tables,
    uint32_t trace_rows,
    uint32_t maximum_shard_columns,
    Audit& out)
{
    out.role_support_topology.clear();
    out.registered_semantic_endpoint_families = 0;
    out.semantically_complete_endpoint_families = 0;
    out.residual_opaque_semantic_families = 0;
    for (const auto& interval : ROLE_ENDPOINT_INTERVALS) {
        Audit::RoleSupportTopologyV1 role;
        role.role = interval.role;
        role.first_endpoint = interval.first;
        role.semantic_endpoint_families = interval.count;
        std::set<uint16_t> complete_endpoints;
        for (uint16_t endpoint = interval.first;
             endpoint < interval.first + interval.count;
             ++endpoint) {
            bool found = false;
            bool all_components_complete = true;
            for (const auto& spec : tables) {
                if (spec.table.role != interval.role ||
                    spec.mapped_endpoint != endpoint) {
                    continue;
                }
                found = true;
                all_components_complete &=
                    spec.semantic_endpoint_complete;
            }
            if (found && all_components_complete) {
                complete_endpoints.insert(endpoint);
            }
        }
        role.semantically_complete_endpoint_families =
            static_cast<uint16_t>(complete_endpoints.size());
        role.residual_opaque_semantic_families =
            interval.count -
            role.semantically_complete_endpoint_families;
        uint32_t namespace_base = 0;
        for (const auto& spec : tables) {
            if (spec.table.role != interval.role) continue;
            const RelationLocalShardManifestV1 manifest =
                BuildRelationLocalShardManifestV1(
                    spec.table, trace_rows,
                    maximum_shard_columns);
            if (!manifest.valid) return false;
            Audit::CanonicalFamilySupportV1 family;
            family.family = spec.family;
            family.role = interval.role;
            family.mapped_endpoint = spec.mapped_endpoint;
            family.role_namespace_base = namespace_base;
            family.namespace_width =
                spec.table.current_width;
            family.constraints =
                static_cast<uint32_t>(
                    spec.table.programs.size());
            family.shards =
                static_cast<uint32_t>(
                    manifest.shards.size());
            family.equality_links =
                static_cast<uint32_t>(
                    manifest.equality_links.size());
            family.leaf_receipts =
                manifest.cost.leaf_receipt_count;
            family.recursive_parents =
                manifest.cost.recursive_parent_count;
            family.exact_proof_instances =
                family.leaf_receipts +
                family.recursive_parents;
            family.proof_instance_shape_manifest_derived =
                true;
            const auto commitments =
                cb::CommitProgramTableForExternalAndRecursiveUse(
                    spec.table);
            family.program_table_commitment =
                commitments.external_sha256d;
            family.recursive_program_table_commitment =
                commitments.recursive_alg_hash;
            family.external_and_recursive_commitments_share_bytes =
                commitments.same_canonical_serialization;
            family.cross_hash_collision_binding_proved =
                commitments.cross_hash_collision_binding_proved;
            family.semantic_endpoint_complete =
                spec.mapped_endpoint != 0 &&
                complete_endpoints.contains(
                    spec.mapped_endpoint);
            family.residual = spec.residual;
            std::set<uint32_t> family_support;
            for (const auto& support : manifest.supports) {
                for (const uint32_t column :
                     support.global_columns) {
                    if (column >= family.namespace_width ||
                        namespace_base >
                            std::numeric_limits<uint32_t>::max() -
                                column) {
                        return false;
                    }
                    family_support.insert(
                        namespace_base + column);
                }
            }
            family.exact_support_columns =
                static_cast<uint32_t>(
                    family_support.size());
            role.support_union.insert(
                role.support_union.end(),
                family_support.begin(),
                family_support.end());
            role.canonical_constraints +=
                family.constraints;
            role.exact_shards += family.shards;
            role.exact_equality_links +=
                family.equality_links;
            ++role.canonical_program_tables;
            role.canonical_families.push_back(
                std::move(family));
            if (namespace_base >
                std::numeric_limits<uint32_t>::max() -
                    spec.table.current_width) {
                return false;
            }
            namespace_base += spec.table.current_width;
        }
        SortUnique(role.support_union);
        role.role_namespace_columns = namespace_base;
        role.exact_support_columns =
            static_cast<uint32_t>(
                role.support_union.size());
        role.namespace_derived_from_executable_bytecode =
            role.canonical_program_tables != 0;
        role.semantic_role_complete =
            role.semantically_complete_endpoint_families ==
            role.semantic_endpoint_families;
        out.registered_semantic_endpoint_families +=
            role.semantic_endpoint_families;
        out.semantically_complete_endpoint_families +=
            role.semantically_complete_endpoint_families;
        out.residual_opaque_semantic_families +=
            role.residual_opaque_semantic_families;
        out.role_support_topology.push_back(
            std::move(role));
    }
    return out.role_support_topology.size() ==
            ROLE_ENDPOINT_INTERVALS.size() &&
        out.registered_semantic_endpoint_families == 52 &&
        out.semantically_complete_endpoint_families == 2 &&
        out.residual_opaque_semantic_families == 50;
}

} // namespace

RelationLocalEmbeddedCtlPlanV1
BuildRelationLocalEmbeddedCtlPlanV1(
    const RelationLocalShardManifestV1& manifest)
{
    RelationLocalEmbeddedCtlPlanV1 out;
    out.shard_manifest_commitment =
        manifest.manifest_commitment;
    if (!manifest.valid ||
        manifest.manifest_commitment.IsNull() ||
        manifest.shards.empty() ||
        manifest.trace_rows < 2 ||
        (manifest.trace_rows &
         (manifest.trace_rows - 1)) != 0) {
        out.note =
            "stage3:relation_local_sharding:"
            "embedded_ctl:manifest";
        return out;
    }

    out.ordered_phase0_roots =
        static_cast<uint32_t>(
            manifest.shards.size());
    out.equality_links =
        static_cast<uint32_t>(
            manifest.equality_links.size());
    out.value_direct_aliases =
        2 * out.equality_links;
    out.exported_terminal_cells =
        4 * out.equality_links;
    out.shards.resize(manifest.shards.size());
    for (uint32_t index = 0;
         index < out.shards.size(); ++index) {
        auto& shard = out.shards[index];
        shard.shard_index = index;
        shard.relation_base_columns =
            static_cast<uint32_t>(
                manifest.shards[index]
                    .global_columns.size());
    }
    for (const auto& link :
         manifest.equality_links) {
        if (link.index >= out.equality_links ||
            link.anchor_shard >= out.shards.size() ||
            link.replica_shard >= out.shards.size() ||
            link.anchor_shard == link.replica_shard ||
            !link.row_index_tagged ||
            !link.challenges_after_all_shard_commitments ||
            link.independent_lanes != 2 ||
            link.tuple_arity != 2) {
            out.note =
                "stage3:relation_local_sharding:"
                "embedded_ctl:link";
            return out;
        }
        out.shards[link.anchor_shard]
            .incident_link_indices.push_back(
                link.index);
        out.shards[link.replica_shard]
            .incident_link_indices.push_back(
                link.index);
    }
    for (auto& shard : out.shards) {
        std::sort(
            shard.incident_link_indices.begin(),
            shard.incident_link_indices.end());
        // VALUE is a direct alias of a relation column. Namespace, stage,
        // row/address and multiplicity are verifier-owned preprocessing.
        // Only the two inverses, two terms and two running sums are Rdep.
        shard.ctl_dependent_columns =
            6 * static_cast<uint32_t>(
                shard.incident_link_indices.size());
        shard.augmented_trace_columns =
            shard.relation_base_columns +
            shard.ctl_dependent_columns;
        shard.exported_terminal_cells =
            2 * static_cast<uint32_t>(
                shard.incident_link_indices.size());
        out.dependent_ctl_columns +=
            shard.ctl_dependent_columns;
        out.maximum_augmented_shard_columns =
            std::max(
                out.maximum_augmented_shard_columns,
                shard.augmented_trace_columns);
    }
    out.split_rap_leaf_proofs =
        static_cast<uint32_t>(
            out.shards.size());
    const auto [parents, levels] =
        ArityFourCounts(
            out.split_rap_leaf_proofs);
    out.arity_four_parent_proofs = parents;
    out.arity_four_levels = levels;

    HashWriter schedule;
    schedule <<
        "BTX_RC_STAGE3_RELATION_LOCAL_EMBEDDED_CTL_PLAN_V1";
    schedule << out.version;
    schedule << out.shard_manifest_commitment;
    schedule << manifest.trace_rows;
    schedule << out.ordered_phase0_roots;
    schedule << out.equality_links;
    for (const auto& shard : out.shards) {
        schedule << shard.shard_index;
        schedule << shard.incident_link_indices;
        schedule << shard.relation_base_columns;
        schedule << shard.ctl_dependent_columns;
        schedule << shard.augmented_trace_columns;
        schedule << shard.exported_terminal_cells;
    }
    out.coordinator_schedule_commitment =
        schedule.GetHash();
    out.all_values_directly_alias_relation_columns =
        out.value_direct_aliases ==
            2 * out.equality_links;
    out.all_base_roots_precede_challenges = true;
    out.dual_lanes_domain_separated = true;
    out.degree_two_n_coeffs_equal_trace_rows = true;
    out.split_rap_shape_compatible =
        out.maximum_augmented_shard_columns + 1 <=
            16384;
    out.augmented_child_proof_builder_executable =
        false;
    out.normalized_parent_verifier_executable =
        false;
    out.recursively_consumed_equality_links = 0;
    out.recursively_consumed_leaf_proofs = 0;
    out.recursive_consumption_complete = false;
    out.valid =
        !out.coordinator_schedule_commitment.IsNull() &&
        out.all_values_directly_alias_relation_columns &&
        out.split_rap_shape_compatible;
    out.note = out.valid
        ? "stage3:relation_local_sharding:"
          "embedded_ctl:phase_order_and_direct_alias_complete;"
          "augmented_air_builder_and_recursive_vcs_open"
        : "stage3:relation_local_sharding:"
          "embedded_ctl:shape";
    return out;
}

bool ValidateRelationLocalEmbeddedCtlPlanV1(
    const RelationLocalShardManifestV1& manifest,
    const RelationLocalEmbeddedCtlPlanV1& plan,
    std::string* why)
{
    const RelationLocalEmbeddedCtlPlanV1 expected =
        BuildRelationLocalEmbeddedCtlPlanV1(manifest);
    if (!expected.valid || !plan.valid ||
        plan.version != 1 ||
        plan.augmented_child_proof_builder_executable ||
        plan.normalized_parent_verifier_executable ||
        plan.recursive_consumption_complete ||
        plan.recursively_consumed_equality_links != 0 ||
        plan.recursively_consumed_leaf_proofs != 0 ||
        plan != expected) {
        return Fail(
            why,
            "embedded_ctl:plan_substitution");
    }
    return true;
}

RelationLocalShardManifestV1
BuildRelationLocalShardManifestV1(
    const cb::ProgramTable& table,
    uint32_t trace_rows,
    uint32_t maximum_shard_columns)
{
    RelationLocalShardManifestV1 out;
    out.role = table.role;
    out.trace_rows = trace_rows;
    out.original_columns = table.current_width;
    out.original_constraints =
        static_cast<uint32_t>(
            table.programs.size());
    out.maximum_shard_columns =
        maximum_shard_columns;
    if (!cb::ValidateProgramTable(table) ||
        !IsPowerOfTwo(trace_rows) ||
        maximum_shard_columns == 0 ||
        maximum_shard_columns >
            kRelationLocalShardColumnCapV1) {
        out.note =
            "stage3:relation_local_sharding:shape";
        return out;
    }
    out.original_program_table_commitment =
        cb::CommitProgramTable(table);
    if (out.original_program_table_commitment.IsNull()) {
        out.note =
            "stage3:relation_local_sharding:table_commitment";
        return out;
    }
    out.supports.reserve(table.programs.size());
    for (const auto& program : table.programs) {
        ConstraintSupportV1 support =
            BuildSupport(program);
        if (support.program_commitment.IsNull() ||
            support.global_columns.size() >
                maximum_shard_columns) {
            out.note =
                "stage3:relation_local_sharding:"
                "constraint_exceeds_cap";
            return out;
        }
        out.supports.push_back(std::move(support));
    }

    // Canonical overlap-greedy hypergraph partition. Empty-support constant
    // constraints use global column zero as a harmless committed carrier so
    // the current ProgramTable shape remains nonzero.
    for (const auto& support : out.supports) {
        std::vector<uint32_t> support_columns =
            support.global_columns;
        if (support_columns.empty()) {
            support_columns.push_back(0);
        }
        uint32_t selected =
            std::numeric_limits<uint32_t>::max();
        uint32_t best_overlap = 0;
        for (uint32_t index = 0;
             index < out.shards.size(); ++index) {
            const auto combined = UnionColumns(
                out.shards[index].global_columns,
                support_columns);
            if (combined.size() >
                maximum_shard_columns) {
                continue;
            }
            const uint32_t overlap =
                IntersectionSize(
                    out.shards[index].global_columns,
                    support_columns);
            if (selected ==
                    std::numeric_limits<uint32_t>::max() ||
                overlap > best_overlap) {
                selected = index;
                best_overlap = overlap;
            }
        }
        if (selected ==
            std::numeric_limits<uint32_t>::max()) {
            RelationLocalShardV1 shard;
            shard.index =
                static_cast<uint32_t>(
                    out.shards.size());
            shard.global_columns =
                std::move(support_columns);
            out.shards.push_back(std::move(shard));
            selected =
                static_cast<uint32_t>(
                    out.shards.size() - 1);
        } else {
            out.shards[selected].global_columns =
                UnionColumns(
                    out.shards[selected].global_columns,
                    support_columns);
        }
        out.shards[selected]
            .constraint_ordinals.push_back(
                support.ordinal);
    }

    for (auto& shard : out.shards) {
        shard.projected_table.version =
            cb::kConstraintBytecodeVersion;
        shard.projected_table.role = table.role;
        shard.projected_table.current_width =
            static_cast<uint32_t>(
                shard.global_columns.size());
        shard.projected_table.next_width =
            shard.projected_table.current_width;
        shard.projected_table.programs.reserve(
            shard.constraint_ordinals.size());
        for (uint32_t local_ordinal = 0;
             local_ordinal <
                 shard.constraint_ordinals.size();
             ++local_ordinal) {
            const uint32_t original_ordinal =
                shard.constraint_ordinals[
                    local_ordinal];
            cb::Program projected;
            if (original_ordinal >=
                    table.programs.size() ||
                !ProjectProgram(
                    table.programs[original_ordinal],
                    shard.global_columns,
                    local_ordinal,
                    projected)) {
                out.note =
                    "stage3:relation_local_sharding:"
                    "projection";
                return out;
            }
            shard.projected_table.programs.push_back(
                std::move(projected));
        }
        if (!cb::ValidateProgramTable(
                shard.projected_table)) {
            out.note =
                "stage3:relation_local_sharding:"
                "projected_table";
            return out;
        }
        shard.projected_table_commitment =
            cb::CommitProgramTable(
                shard.projected_table);
        if (shard.projected_table_commitment.IsNull()) {
            out.note =
                "stage3:relation_local_sharding:"
                "projected_commitment";
            return out;
        }
    }

    std::map<uint32_t, std::vector<uint32_t>>
        column_occurrences;
    for (const auto& shard : out.shards) {
        for (uint32_t global :
             shard.global_columns) {
            column_occurrences[global].push_back(
                shard.index);
        }
    }
    for (const auto& [global, occurrences] :
         column_occurrences) {
        if (occurrences.size() < 2) continue;
        const uint32_t anchor = occurrences.front();
        for (uint32_t i = 1;
             i < occurrences.size(); ++i) {
            CrossShardEqualityLinkV1 link;
            link.index =
                static_cast<uint32_t>(
                    out.equality_links.size());
            link.global_column = global;
            link.anchor_shard = anchor;
            link.replica_shard = occurrences[i];
            link.anchor_local_column =
                LocalColumn(
                    out.shards[anchor].global_columns,
                    global);
            link.replica_local_column =
                LocalColumn(
                    out.shards[occurrences[i]]
                        .global_columns,
                    global);
            if (link.anchor_local_column ==
                    std::numeric_limits<uint32_t>::max() ||
                link.replica_local_column ==
                    std::numeric_limits<uint32_t>::max()) {
                out.note =
                    "stage3:relation_local_sharding:"
                    "equality_column";
                return out;
            }
            out.equality_links.push_back(link);
        }
    }

    out.cost.trace_rows = trace_rows;
    out.cost.original_columns =
        out.original_columns;
    out.cost.shard_count =
        static_cast<uint32_t>(out.shards.size());
    out.cost.equality_link_count =
        static_cast<uint32_t>(
            out.equality_links.size());
    out.cost.leaf_receipt_count =
        out.cost.shard_count +
        out.cost.equality_link_count;
    for (const auto& shard : out.shards) {
        out.cost.maximum_shard_columns =
            std::max(
                out.cost.maximum_shard_columns,
                static_cast<uint32_t>(
                    shard.global_columns.size()));
    }
    if (!CheckedCost(out.cost, out.shards)) {
        out.note =
            "stage3:relation_local_sharding:cost_overflow";
        return out;
    }
    uint32_t inputs = out.cost.leaf_receipt_count;
    uint32_t level_index = 0;
    while (inputs > 1) {
        const uint32_t parents =
            (inputs +
             kRelationLocalShardRecursionArityV1 - 1) /
            kRelationLocalShardRecursionArityV1;
        out.aggregation_levels.push_back(
            {level_index, inputs, parents});
        out.cost.recursive_parent_count += parents;
        inputs = parents;
        ++level_index;
    }
    out.cost.recursive_levels = level_index;

    out.all_constraints_explicit = true;
    out.exact_constraint_partition = true;
    out.exact_column_projection = true;
    // Each original polynomial constraint is checked in exactly one local
    // quotient. Their conjunction is therefore equivalent to one monolithic
    // quotient; there is no independent "global quotient" to link.
    out.quotient_conjunction_equivalent = true;
    out.shared_global_column_ids_explicit = true;
    out.shared_global_column_roots_bound = false;
    out.global_soundness_composition_proved = false;
    out.backend_leaf_shape_supported =
        out.cost.maximum_shard_columns + 1 <=
            16384;
    // Mathematical obligations are explicit, but no current executable
    // SplitRAP parent verifies the two equality terminals or child proofs.
    out.equality_ctl_proofs_executable =
        out.equality_links.empty();
    out.equality_terminals_recursively_consumed =
        false;
    out.normalized_arity_four_parent_executable =
        false;
    out.production_authority_ready = false;
    out.manifest_commitment = CommitManifest(out);
    if (out.manifest_commitment.IsNull()) {
        out.note =
            "stage3:relation_local_sharding:"
            "manifest_commitment";
        return out;
    }
    out.valid = true;
    out.note =
        out.equality_links.empty()
            ? "stage3:relation_local_sharding:"
              "exact_local_decomposition;"
              "recursive_parent_open"
            : "stage3:relation_local_sharding:"
              "exact_local_decomposition;"
              "row_index_dual_logup_and_recursive_parent_open";
    return out;
}

bool ValidateRelationLocalShardManifestV1(
    const cb::ProgramTable& table,
    const RelationLocalShardManifestV1& manifest,
    std::string* why)
{
    if (manifest.version !=
            kRelationLocalShardManifestVersionV1 ||
        !manifest.valid ||
        manifest.production_authority_ready ||
        manifest.global_soundness_composition_proved ||
        manifest.equality_terminals_recursively_consumed ||
        manifest.normalized_arity_four_parent_executable ||
        !manifest.shared_global_column_ids_explicit ||
        manifest.shared_global_column_roots_bound ||
        manifest.cost.timing_measured ||
        manifest.cost.timing_target_met) {
        return Fail(why, "manifest_flags");
    }
    const RelationLocalShardManifestV1 expected =
        BuildRelationLocalShardManifestV1(
            table,
            manifest.trace_rows,
            manifest.maximum_shard_columns);
    if (!expected.valid || manifest != expected) {
        return Fail(why, "manifest_substitution");
    }
    return true;
}

CurrentRelationLocalProductionAuditV1
AssessCurrentRelationLocalProductionAuditV1()
{
    CurrentRelationLocalProductionAuditV1 out;
    const auto migration =
        cb::CurrentRoleMigrationInventory();
    out.required_roles =
        static_cast<uint32_t>(migration.size());
    for (const auto& role : migration) {
        switch (role.state) {
        case cb::MigrationState::Complete:
            ++out.fully_migrated_roles;
            break;
        case cb::MigrationState::Partial:
            ++out.partially_migrated_roles;
            break;
        case cb::MigrationState::NotStarted:
            ++out.unmigrated_roles;
            break;
        }
        if (role.opaque_callbacks_remain) {
            ++out.roles_with_opaque_callbacks;
        }
    }
    auto add_explicit_table =
        [&out](const CanonicalTableSpec& spec) {
            const cb::ProgramTable& table = spec.table;
            const RelationLocalShardManifestV1 manifest =
                BuildRelationLocalShardManifestV1(
                    table, out.declared_trace_rows,
                    out.maximum_shard_columns);
            if (!manifest.valid) return false;
            ++out.explicit_local_program_tables;
            out.explicit_local_constraints +=
                static_cast<uint32_t>(
                    table.programs.size());
            // Tables have independent trace namespaces at this seam. Count
            // only columns actually loaded by canonical bytecode, not unused
            // preprocessed/witness columns in the enclosing trace width.
            std::set<uint32_t> support_columns;
            for (const auto& support : manifest.supports) {
                support_columns.insert(
                    support.global_columns.begin(),
                    support.global_columns.end());
            }
            out.exact_support_columns +=
                static_cast<uint32_t>(
                    support_columns.size());
            out.exact_namespace_columns +=
                table.current_width;
            out.explicit_local_shards +=
                static_cast<uint32_t>(
                    manifest.shards.size());
            out.explicit_local_equality_links +=
                static_cast<uint32_t>(
                    manifest.equality_links.size());
            const uint32_t proof_instances =
                manifest.cost.leaf_receipt_count +
                manifest.cost.recursive_parent_count;
            out.explicit_local_proof_instances +=
                proof_instances;
            if (spec.semantic_endpoint_complete) {
                out.semantically_complete_local_proof_instances +=
                    proof_instances;
            }
            return true;
        };
    bool tables_ok = true;
    const std::vector<CanonicalTableSpec> tables =
        BuildCurrentCanonicalTableSpecs(tables_ok);
    for (const auto& spec : tables) {
        tables_ok =
            add_explicit_table(spec) &&
            tables_ok;
    }
    const bool topology_ok =
        PopulateRoleSupportTopology(
            tables,
            out.declared_trace_rows,
            out.maximum_shard_columns,
            out);
    out.shard_count_lower_bound =
        (out.declared_columns +
         out.maximum_shard_columns - 1) /
        out.maximum_shard_columns;
    const auto [parents, levels] =
        ArityFourCounts(
            out.shard_count_lower_bound);
    out.recursive_parent_count_lower_bound =
        parents;
    out.recursive_levels_lower_bound =
        levels;
    out.proof_instances_lower_bound =
        out.shard_count_lower_bound +
        out.recursive_parent_count_lower_bound;
    out.conservative_union_bound_loss_bits =
        CeilLog2(out.proof_instances_lower_bound);
    out.conservative_global_bits_upper_bound =
        out.known_recursive_bits_integer >
                out.conservative_union_bound_loss_bits
            ? out.known_recursive_bits_integer -
                out.conservative_union_bound_loss_bits
            : 0;
    out.required_per_proof_bits_for_100_global =
        100 +
        out.conservative_union_bound_loss_bits;
    out.declared_width_manifest_derived = false;
    out.partial_support_hypergraph_available =
        tables_ok && topology_ok &&
        out.explicit_local_program_tables == 25;
    out.exact_support_hypergraph_available = false;
    out.recursive_program_commitments_available =
        topology_ok &&
        std::all_of(
            out.role_support_topology.begin(),
            out.role_support_topology.end(),
            [](const Audit::RoleSupportTopologyV1& role) {
                return std::all_of(
                    role.canonical_families.begin(),
                    role.canonical_families.end(),
                    [](const Audit::CanonicalFamilySupportV1& family) {
                        return family
                                   .external_and_recursive_commitments_share_bytes &&
                            std::any_of(
                                family
                                    .recursive_program_table_commitment
                                    .begin(),
                                family
                                    .recursive_program_table_commitment
                                    .end(),
                                [](gf::Fp value) {
                                    return gf::Canonical(value) != 0;
                                });
                    });
            });
    out.cross_hash_program_commitment_binding_proved =
        false;
    out.proof_instance_multiplicity_manifest_derived =
        false;
    out.manifest_derived_global_proof_instances = 0;
    out.manifest_derived_scheduled_proof_instances = 0;
    out.all_registered_constraints_explicit =
        out.roles_with_opaque_callbacks == 0 &&
        out.fully_migrated_roles ==
            out.required_roles;
    out.all_cross_shard_equalities_executable =
        false;
    out.normalized_recursive_parent_executable =
        false;
    out.global_soundness_composition_proved =
        false;
    out.production_root_timing_measured = false;
    out.sub_900ms_root_verified = false;
    out.production_candidate = false;
    out.valid =
        out.required_roles == 14 &&
        out.fully_migrated_roles == 0 &&
        out.partially_migrated_roles == 14 &&
        out.unmigrated_roles == 0 &&
        out.roles_with_opaque_callbacks == 14 &&
        out.partial_support_hypergraph_available &&
        out.exact_support_columns == 790 &&
        out.exact_namespace_columns == 825 &&
        out.explicit_local_program_tables == 25 &&
        out.explicit_local_constraints == 804 &&
        out.explicit_local_shards == 25 &&
        out.explicit_local_equality_links == 0 &&
        out.explicit_local_proof_instances == 25 &&
        out.semantically_complete_local_proof_instances == 3 &&
        out.recursive_program_commitments_available &&
        !out.cross_hash_program_commitment_binding_proved &&
        out.registered_semantic_endpoint_families == 52 &&
        out.semantically_complete_endpoint_families == 2 &&
        out.residual_opaque_semantic_families == 50 &&
        out.role_support_topology.size() == 14 &&
        !out.proof_instance_multiplicity_manifest_derived &&
        out.manifest_derived_global_proof_instances == 0 &&
        out.manifest_derived_scheduled_proof_instances == 0 &&
        out.shard_count_lower_bound == 244 &&
        out.recursive_parent_count_lower_bound == 82 &&
        out.recursive_levels_lower_bound == 4 &&
        out.proof_instances_lower_bound == 326 &&
        out.conservative_union_bound_loss_bits == 9 &&
        out.conservative_global_bits_upper_bound == 86 &&
        out.required_per_proof_bits_for_100_global == 109 &&
        !kRelationLocalShardingProductionAuthorityV1;
    out.note = out.valid
        ? "stage3:relation_local_sharding:"
          "no_production_candidate;"
          "124802_width_is_planner_only;"
          "twenty_five_local_program_tables_have_exact_support;"
          "two_public_input_endpoint_relations_are_semantically_complete;"
          "fifty_semantic_endpoint_families_remain_residual;"
          "complete_support_topology_multiplicity_ctl_parent_soundness_and_timing_open"
        : "stage3:relation_local_sharding:"
          "current_inventory_changed";
    return out;
}

bool ValidateCurrentRelationLocalProductionAuditV1(
    const CurrentRelationLocalProductionAuditV1& audit,
    std::string* why)
{
    const CurrentRelationLocalProductionAuditV1 expected =
        AssessCurrentRelationLocalProductionAuditV1();
    if (!expected.valid || !audit.valid ||
        audit.production_candidate ||
        audit.sub_900ms_root_verified ||
        audit != expected) {
        return Fail(why, "production_audit_substitution");
    }
    return true;
}

} // namespace matmul::v4::rc::stage3_relation_local_sharding
