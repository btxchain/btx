// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_gkr_field_ext3.h>
#include <matmul/matmul_v4_rc_stage3_coupled_air.h>
#include <matmul/matmul_v4_rc_stage3_episode_air.h>
#include <matmul/matmul_v4_rc_stage3_relation_local_sharding.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

namespace {

namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace rl =
    matmul::v4::rc::stage3_relation_local_sharding;
namespace gf =
    matmul::v4::rc::gkr_field;

cb::Instruction Load(
    cb::Opcode opcode, uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode, uint32_t lhs, uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::Program Constraint(
    uint32_t ordinal,
    uint32_t lhs_column,
    uint32_t rhs_column,
    bool rhs_is_next,
    cb::Opcode operation,
    uint32_t degree)
{
    cb::Program out;
    out.role =
        matmul::v4::rc::RCStage3RelationRole::
            CoupledBank;
    out.constraint_ordinal = ordinal;
    out.kind =
        matmul::v4::rc::air_quotient::
            AirKind::kEverywhere;
    out.declared_degree = degree;
    out.current_width = 6;
    out.next_width = 6;
    out.instructions = {
        Load(cb::Opcode::Current, lhs_column),
        Load(
            rhs_is_next
                ? cb::Opcode::Next
                : cb::Opcode::Current,
            rhs_column),
        Binary(operation, 0, 1),
    };
    return out;
}

cb::ProgramTable ToyTable()
{
    cb::ProgramTable out;
    out.role =
        matmul::v4::rc::RCStage3RelationRole::
            CoupledBank;
    out.current_width = 6;
    out.next_width = 6;
    out.programs = {
        Constraint(
            0, 0, 1, false,
            cb::Opcode::Sub, 1),
        Constraint(
            1, 1, 2, true,
            cb::Opcode::Mul, 2),
        Constraint(
            2, 3, 4, false,
            cb::Opcode::Sub, 1),
        Constraint(
            3, 4, 5, false,
            cb::Opcode::Sub, 1),
    };
    return out;
}

std::vector<gf::Fp3> ProjectValues(
    const std::vector<gf::Fp3>& global,
    const std::vector<uint32_t>& columns)
{
    std::vector<gf::Fp3> out;
    out.reserve(columns.size());
    for (uint32_t column : columns) {
        out.push_back(global[column]);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_relation_local_sharding_tests)

BOOST_AUTO_TEST_CASE(
    bytecode_support_projection_is_exact_and_partitioned)
{
    const cb::ProgramTable table = ToyTable();
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    const rl::RelationLocalShardManifestV1 manifest =
        rl::BuildRelationLocalShardManifestV1(
            table, 8, 2);
    BOOST_REQUIRE_MESSAGE(
        manifest.valid, manifest.note);
    BOOST_CHECK_EQUAL(manifest.supports.size(), 4U);
    BOOST_CHECK_EQUAL(manifest.shards.size(), 4U);
    BOOST_CHECK_EQUAL(
        manifest.equality_links.size(), 2U);
    BOOST_CHECK_EQUAL(
        manifest.cost.leaf_receipt_count, 6U);
    BOOST_CHECK_EQUAL(
        manifest.cost.recursive_parent_count, 3U);
    BOOST_CHECK_EQUAL(
        manifest.cost.recursive_levels, 2U);
    BOOST_CHECK_EQUAL(
        manifest.cost.maximum_shard_columns, 2U);
    BOOST_CHECK_EQUAL(
        manifest.cost.sharded_trace_cells, 64U);
    BOOST_CHECK_EQUAL(
        manifest.cost.sharded_trace_bytes, 1536U);
    BOOST_CHECK_EQUAL(
        manifest.cost
            .direct_opening_value_bytes_lower_bound,
        110592U);
    BOOST_CHECK(manifest.all_constraints_explicit);
    BOOST_CHECK(manifest.exact_constraint_partition);
    BOOST_CHECK(manifest.exact_column_projection);
    BOOST_CHECK(
        manifest.quotient_conjunction_equivalent);
    BOOST_CHECK(
        !manifest.global_soundness_composition_proved);
    BOOST_CHECK(
        manifest.backend_leaf_shape_supported);
    BOOST_CHECK(
        !manifest.equality_ctl_proofs_executable);
    BOOST_CHECK(
        !manifest
             .equality_terminals_recursively_consumed);
    BOOST_CHECK(
        !manifest
             .normalized_arity_four_parent_executable);
    BOOST_CHECK(
        !manifest.production_authority_ready);

    std::vector<gf::Fp3> current(6);
    std::vector<gf::Fp3> next(6);
    for (uint32_t i = 0; i < 6; ++i) {
        current[i] = gf::Fp3::FromFp(
            gf::FromU64(11 + i));
        next[i] = gf::Fp3::FromFp(
            gf::FromU64(31 + 2 * i));
    }
    for (const auto& shard : manifest.shards) {
        const auto local_current =
            ProjectValues(
                current, shard.global_columns);
        const auto local_next =
            ProjectValues(
                next, shard.global_columns);
        for (uint32_t local = 0;
             local <
                 shard.constraint_ordinals.size();
             ++local) {
            const uint32_t original =
                shard.constraint_ordinals[local];
            gf::Fp3 expected;
            gf::Fp3 actual;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[original],
                current, next, expected));
            BOOST_REQUIRE(cb::EvaluateProgram(
                shard.projected_table.programs[local],
                local_current, local_next, actual));
            BOOST_CHECK(gf::Eq(expected, actual));
        }
    }

    for (const auto& link :
         manifest.equality_links) {
        BOOST_CHECK(link.row_index_tagged);
        BOOST_CHECK_EQUAL(link.tuple_arity, 2U);
        BOOST_CHECK_EQUAL(
            link.independent_lanes, 2U);
        BOOST_CHECK(
            link
                .challenges_after_all_shard_commitments);
    }
    std::string why;
    BOOST_CHECK(
        rl::ValidateRelationLocalShardManifestV1(
            table, manifest, &why));
}

BOOST_AUTO_TEST_CASE(
    manifest_omission_reorder_and_promotion_fail_closed)
{
    const cb::ProgramTable table = ToyTable();
    const auto manifest =
        rl::BuildRelationLocalShardManifestV1(
            table, 8, 2);
    BOOST_REQUIRE(manifest.valid);
    std::string why;

    auto omission = manifest;
    omission.equality_links.pop_back();
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            table, omission, &why));

    auto reorder = manifest;
    std::swap(
        reorder.shards[0],
        reorder.shards[1]);
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            table, reorder, &why));

    auto untagged = manifest;
    untagged.equality_links[0]
        .row_index_tagged = false;
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            table, untagged, &why));

    auto promoted = manifest;
    promoted.production_authority_ready = true;
    promoted.global_soundness_composition_proved =
        true;
    promoted.cost.timing_measured = true;
    promoted.cost.timing_target_met = true;
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            table, promoted, &why));

    auto changed_program = table;
    changed_program.programs[0]
        .instructions[0].lhs = 2;
    BOOST_REQUIRE(
        cb::ValidateProgramTable(changed_program));
    BOOST_CHECK(
        !rl::ValidateRelationLocalShardManifestV1(
            changed_program, manifest, &why));
}

BOOST_AUTO_TEST_CASE(
    embedded_ctl_plan_is_phase_ordered_and_directly_aliases_values)
{
    const cb::ProgramTable table = ToyTable();
    const auto manifest =
        rl::BuildRelationLocalShardManifestV1(
            table, 8, 2);
    BOOST_REQUIRE(manifest.valid);
    const auto plan =
        rl::BuildRelationLocalEmbeddedCtlPlanV1(
            manifest);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK_EQUAL(plan.ordered_phase0_roots, 4U);
    BOOST_CHECK_EQUAL(plan.equality_links, 2U);
    BOOST_CHECK_EQUAL(plan.value_direct_aliases, 4U);
    BOOST_CHECK_EQUAL(
        plan.dependent_ctl_columns, 24U);
    BOOST_CHECK_EQUAL(
        plan.exported_terminal_cells, 8U);
    BOOST_CHECK_EQUAL(
        plan.maximum_augmented_shard_columns, 8U);
    BOOST_CHECK_EQUAL(plan.split_rap_leaf_proofs, 4U);
    BOOST_CHECK_EQUAL(
        plan.arity_four_parent_proofs, 1U);
    BOOST_CHECK_EQUAL(plan.arity_four_levels, 1U);
    BOOST_CHECK(
        plan.all_values_directly_alias_relation_columns);
    BOOST_CHECK(plan.all_base_roots_precede_challenges);
    BOOST_CHECK(plan.dual_lanes_domain_separated);
    BOOST_CHECK(
        plan.degree_two_n_coeffs_equal_trace_rows);
    BOOST_CHECK(plan.split_rap_shape_compatible);
    BOOST_CHECK(
        !plan.augmented_child_proof_builder_executable);
    BOOST_CHECK(
        !plan.normalized_parent_verifier_executable);
    BOOST_CHECK_EQUAL(
        plan.recursively_consumed_equality_links, 0U);
    BOOST_CHECK_EQUAL(
        plan.recursively_consumed_leaf_proofs, 0U);
    BOOST_CHECK(!plan.recursive_consumption_complete);
    for (const auto& shard : plan.shards) {
        BOOST_CHECK_EQUAL(
            shard.incident_link_indices.size(), 1U);
        BOOST_CHECK_EQUAL(
            shard.ctl_dependent_columns, 6U);
        BOOST_CHECK_EQUAL(
            shard.exported_terminal_cells, 2U);
    }

    std::string why;
    BOOST_CHECK(
        rl::ValidateRelationLocalEmbeddedCtlPlanV1(
            manifest, plan, &why));

    auto omitted = plan;
    omitted.shards[0]
        .incident_link_indices.clear();
    BOOST_CHECK(
        !rl::ValidateRelationLocalEmbeddedCtlPlanV1(
            manifest, omitted, &why));
    auto reordered = plan;
    std::swap(reordered.shards[0], reordered.shards[1]);
    BOOST_CHECK(
        !rl::ValidateRelationLocalEmbeddedCtlPlanV1(
            manifest, reordered, &why));
    auto promoted = plan;
    promoted.normalized_parent_verifier_executable =
        true;
    promoted.recursively_consumed_equality_links = 2;
    promoted.recursively_consumed_leaf_proofs = 4;
    promoted.recursive_consumption_complete = true;
    BOOST_CHECK(
        !rl::ValidateRelationLocalEmbeddedCtlPlanV1(
            manifest, promoted, &why));
}

BOOST_AUTO_TEST_CASE(
    production_width_is_not_a_support_manifest_or_timing_result)
{
    const auto audit =
        rl::AssessCurrentRelationLocalProductionAuditV1();
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.declared_trace_rows, 256U);
    BOOST_CHECK_EQUAL(audit.declared_columns, 124802U);
    BOOST_CHECK_EQUAL(audit.required_roles, 14U);
    BOOST_CHECK_EQUAL(audit.fully_migrated_roles, 0U);
    BOOST_CHECK_EQUAL(
        audit.partially_migrated_roles, 14U);
    BOOST_CHECK_EQUAL(audit.unmigrated_roles, 0U);
    BOOST_CHECK_EQUAL(
        audit.roles_with_opaque_callbacks, 14U);
    BOOST_CHECK_EQUAL(
        audit.exact_support_columns, 790U);
    BOOST_CHECK_EQUAL(
        audit.exact_namespace_columns, 825U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_program_tables, 25U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_constraints, 804U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_shards, 25U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_equality_links, 0U);
    BOOST_CHECK_EQUAL(
        audit.explicit_local_proof_instances, 25U);
    BOOST_CHECK_EQUAL(
        audit.semantically_complete_local_proof_instances, 3U);
    BOOST_CHECK_EQUAL(
        audit.registered_semantic_endpoint_families, 52U);
    BOOST_CHECK_EQUAL(
        audit.semantically_complete_endpoint_families, 2U);
    BOOST_CHECK_EQUAL(
        audit.residual_opaque_semantic_families, 50U);
    BOOST_REQUIRE_EQUAL(
        audit.role_support_topology.size(), 14U);
    uint32_t topology_tables = 0;
    uint32_t topology_constraints = 0;
    uint32_t topology_namespace_columns = 0;
    uint32_t topology_support_columns = 0;
    uint32_t topology_endpoints = 0;
    uint32_t topology_complete_endpoints = 0;
    uint32_t complete_family_components = 0;
    for (const auto& role : audit.role_support_topology) {
        BOOST_CHECK(
            role.namespace_derived_from_executable_bytecode);
        BOOST_CHECK(!role.semantic_role_complete);
        BOOST_CHECK_EQUAL(
            role.residual_opaque_semantic_families +
                role.semantically_complete_endpoint_families,
            role.semantic_endpoint_families);
        BOOST_CHECK_EQUAL(
            role.support_union.size(),
            role.exact_support_columns);
        BOOST_CHECK(std::is_sorted(
            role.support_union.begin(),
            role.support_union.end()));
        for (const auto& family :
             role.canonical_families) {
            BOOST_CHECK(family.role == role.role);
            BOOST_CHECK(
                !family.program_table_commitment.IsNull());
            BOOST_CHECK(
                family
                    .external_and_recursive_commitments_share_bytes);
            BOOST_CHECK(
                !family.cross_hash_collision_binding_proved);
            BOOST_CHECK(std::any_of(
                family.recursive_program_table_commitment.begin(),
                family.recursive_program_table_commitment.end(),
                [](gf::Fp value) {
                    return gf::Canonical(value) != 0;
                }));
            BOOST_CHECK(
                family.proof_instance_shape_manifest_derived);
            BOOST_CHECK_EQUAL(
                family.exact_proof_instances,
                family.leaf_receipts +
                    family.recursive_parents);
            complete_family_components +=
                family.semantic_endpoint_complete;
            if (family.semantic_endpoint_complete) {
                BOOST_CHECK(
                    family.mapped_endpoint == 1 ||
                    family.mapped_endpoint == 25);
            }
            BOOST_CHECK(!family.residual.empty());
            BOOST_CHECK_LE(
                family.role_namespace_base +
                    family.namespace_width,
                role.role_namespace_columns);
        }
        topology_tables += role.canonical_program_tables;
        topology_constraints += role.canonical_constraints;
        topology_namespace_columns +=
            role.role_namespace_columns;
        topology_support_columns +=
            role.exact_support_columns;
        topology_endpoints +=
            role.semantic_endpoint_families;
        topology_complete_endpoints +=
            role.semantically_complete_endpoint_families;
    }
    BOOST_CHECK_EQUAL(topology_tables, 25U);
    BOOST_CHECK_EQUAL(topology_constraints, 804U);
    BOOST_CHECK_EQUAL(topology_namespace_columns, 825U);
    BOOST_CHECK_EQUAL(topology_support_columns, 790U);
    BOOST_CHECK_EQUAL(topology_endpoints, 52U);
    BOOST_CHECK_EQUAL(topology_complete_endpoints, 2U);
    // Endpoint 1 owns its semantic-memory table. Endpoint 25 owns both its
    // semantic-memory table and compact target-equality table.
    BOOST_CHECK_EQUAL(complete_family_components, 3U);
    BOOST_CHECK_EQUAL(
        audit.shard_count_lower_bound, 244U);
    BOOST_CHECK_EQUAL(
        audit.recursive_parent_count_lower_bound,
        82U);
    BOOST_CHECK_EQUAL(
        audit.recursive_levels_lower_bound, 4U);
    BOOST_CHECK_EQUAL(
        audit.proof_instances_lower_bound, 326U);
    BOOST_CHECK_EQUAL(
        audit.conservative_union_bound_loss_bits,
        9U);
    BOOST_CHECK_EQUAL(
        audit.known_recursive_bits_integer, 95U);
    BOOST_CHECK_EQUAL(
        audit.conservative_global_bits_upper_bound,
        86U);
    BOOST_CHECK_EQUAL(
        audit.required_per_proof_bits_for_100_global,
        109U);
    BOOST_CHECK(
        !audit.declared_width_manifest_derived);
    BOOST_CHECK(
        audit.partial_support_hypergraph_available);
    BOOST_CHECK(
        !audit.exact_support_hypergraph_available);
    BOOST_CHECK(
        audit.recursive_program_commitments_available);
    BOOST_CHECK(
        !audit
             .cross_hash_program_commitment_binding_proved);
    BOOST_CHECK(
        !audit
             .proof_instance_multiplicity_manifest_derived);
    BOOST_CHECK_EQUAL(
        audit.manifest_derived_global_proof_instances,
        0U);
    BOOST_CHECK_EQUAL(
        audit.manifest_derived_scheduled_proof_instances,
        0U);
    BOOST_CHECK(
        !audit.all_registered_constraints_explicit);
    BOOST_CHECK(
        !audit
             .all_cross_shard_equalities_executable);
    BOOST_CHECK(
        !audit
             .normalized_recursive_parent_executable);
    BOOST_CHECK(
        !audit.global_soundness_composition_proved);
    BOOST_CHECK(
        !audit.production_root_timing_measured);
    BOOST_CHECK(!audit.sub_900ms_root_verified);
    BOOST_CHECK(!audit.production_candidate);

    std::string why;
    BOOST_CHECK(
        rl::
            ValidateCurrentRelationLocalProductionAuditV1(
                audit, &why));
    auto promoted = audit;
    promoted.production_candidate = true;
    promoted.sub_900ms_root_verified = true;
    BOOST_CHECK(
        !rl::
             ValidateCurrentRelationLocalProductionAuditV1(
                 promoted, &why));
    auto remapped = audit;
    BOOST_REQUIRE(
        !remapped.role_support_topology.front()
             .support_union.empty());
    ++remapped.role_support_topology.front()
          .support_union.front();
    BOOST_CHECK(
        !rl::
             ValidateCurrentRelationLocalProductionAuditV1(
                 remapped, &why));
    static_assert(
        !rl::
            kRelationLocalShardingProductionAuthorityV1);
}

BOOST_AUTO_TEST_CASE(
    seven_registered_local_kernels_use_canonical_bytecode)
{
    using matmul::v4::rc::BuildRCStage3CoupledLocalKernelProgramTable;
    using matmul::v4::rc::BuildRCStage3EpisodeLocalKernelProgramTable;
    using matmul::v4::rc::RCStage3EpisodeAirFamily;
    using matmul::v4::rc::RCStage3RelationRole;

    std::vector<cb::ProgramTable> tables;
    for (const auto family : {
             RCStage3EpisodeAirFamily::GemmEndpointFp3V1,
             RCStage3EpisodeAirFamily::WiringEqualityFp3V1}) {
        cb::ProgramTable table;
        BOOST_REQUIRE(
            BuildRCStage3EpisodeLocalKernelProgramTable(
                family, table));
        tables.push_back(std::move(table));
    }
    for (const auto role : {
             RCStage3RelationRole::CoupledBank,
             RCStage3RelationRole::CoupledGemm,
             RCStage3RelationRole::CoupledExchange,
             RCStage3RelationRole::CoupledPermutation,
             RCStage3RelationRole::CoupledMix}) {
        cb::ProgramTable table;
        BOOST_REQUIRE(
            BuildRCStage3CoupledLocalKernelProgramTable(
                role, table));
        tables.push_back(std::move(table));
    }
    BOOST_REQUIRE_EQUAL(tables.size(), 7U);
    const std::vector<uint32_t> expected_widths{
        3, 2, 10, 5, 2, 2, 280};
    const std::vector<uint32_t> expected_constraints{
        1, 1, 10, 6, 1, 1, 288};
    uint32_t columns = 0;
    uint32_t constraints = 0;
    for (uint32_t table_index = 0;
         table_index < tables.size(); ++table_index) {
        const auto& table = tables[table_index];
        BOOST_REQUIRE(cb::ValidateProgramTable(table));
        BOOST_CHECK_EQUAL(
            table.current_width,
            expected_widths[table_index]);
        BOOST_CHECK_EQUAL(
            table.programs.size(),
            expected_constraints[table_index]);
        columns += table.current_width;
        constraints +=
            static_cast<uint32_t>(table.programs.size());

        matmul::v4::rc::air_quotient::
            AirConstraintSystem<gf::Fp3> adapted;
        BOOST_REQUIRE(
            cb::BuildAirConstraintSystemFromProgramTable(
                table, 2, adapted));
        BOOST_REQUIRE_EQUAL(
            adapted.constraints.size(),
            table.programs.size());
        std::vector<gf::Fp3> current(
            table.current_width);
        std::vector<gf::Fp3> next(
            table.next_width);
        for (uint32_t column = 0;
             column < table.current_width; ++column) {
            current[column] =
                gf::FromU64_3(
                    17 + 31 * table_index + column);
            next[column] =
                gf::FromU64_3(
                    101 + 43 * table_index + column);
        }
        for (uint32_t ordinal = 0;
             ordinal < table.programs.size();
             ++ordinal) {
            gf::Fp3 interpreted;
            BOOST_REQUIRE(cb::EvaluateProgram(
                table.programs[ordinal],
                current, next, interpreted));
            const gf::Fp3 callback =
                adapted.constraints[ordinal].eval(
                    current, next);
            BOOST_CHECK(gf::Eq(
                interpreted, callback));
        }

        const auto manifest =
            rl::BuildRelationLocalShardManifestV1(
                table, 256);
        BOOST_REQUIRE_MESSAGE(
            manifest.valid, manifest.note);
        BOOST_CHECK(
            manifest.shared_global_column_ids_explicit);
        BOOST_CHECK(
            !manifest.shared_global_column_roots_bound);
        BOOST_CHECK_EQUAL(manifest.shards.size(), 1U);

        auto mutated = table;
        auto& load =
            *std::find_if(
                mutated.programs.front()
                    .instructions.begin(),
                mutated.programs.front()
                    .instructions.end(),
                [](const cb::Instruction& instruction) {
                    return instruction.opcode ==
                            cb::Opcode::Current ||
                        instruction.opcode ==
                            cb::Opcode::Next;
                });
        load.lhs =
            (load.lhs + 1) % table.current_width;
        BOOST_REQUIRE(cb::ValidateProgramTable(mutated));
        BOOST_CHECK(
            cb::CommitProgramTable(mutated) !=
            cb::CommitProgramTable(table));
        BOOST_CHECK(
            cb::CommitProgramTableAlgHash(mutated) !=
            cb::CommitProgramTableAlgHash(table));
        const auto commitments =
            cb::CommitProgramTableForExternalAndRecursiveUse(table);
        BOOST_CHECK(
            commitments.external_sha256d ==
            cb::CommitProgramTable(table));
        BOOST_CHECK(
            commitments.recursive_alg_hash ==
            cb::CommitProgramTableAlgHash(table));
        BOOST_CHECK(commitments.same_canonical_serialization);
        BOOST_CHECK(
            !commitments.cross_hash_collision_binding_proved);
        std::string why;
        BOOST_CHECK(
            !rl::ValidateRelationLocalShardManifestV1(
                mutated, manifest, &why));
    }
    BOOST_CHECK_EQUAL(columns, 304U);
    BOOST_CHECK_EQUAL(constraints, 308U);

    cb::ProgramTable unsupported;
    std::string why;
    // All three episode AIR families are now bytecode-backed. Reject an
    // out-of-enum family so the fail-closed default arm stays covered.
    BOOST_CHECK(
        !BuildRCStage3EpisodeLocalKernelProgramTable(
            static_cast<RCStage3EpisodeAirFamily>(0xff),
            unsupported, &why));
    // EpisodeExtract + CoupledExtract and the two SHA256d hash roles are
    // migrated to canonical bytecode; the local-kernel builders return
    // real tables.
    cb::ProgramTable migrated;
    BOOST_CHECK(
        BuildRCStage3EpisodeLocalKernelProgramTable(
            RCStage3EpisodeAirFamily::
                ExtractSamplerCoreFp3V1,
            migrated, &why));
    BOOST_CHECK(
        BuildRCStage3CoupledLocalKernelProgramTable(
            RCStage3RelationRole::CoupledExtract,
            migrated, &why));
    BOOST_CHECK(
        BuildRCStage3CoupledLocalKernelProgramTable(
            RCStage3RelationRole::CoupledBarrier,
            migrated, &why));
    BOOST_CHECK(
        BuildRCStage3CoupledLocalKernelProgramTable(
            RCStage3RelationRole::CoupledDigest,
            migrated, &why));
}

BOOST_AUTO_TEST_CASE(
    endpoint28_signed_byte_bridge_is_canonical_and_mutation_sensitive)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        matmul::v4::rc::
            BuildRCStage3CoupledBankByteBridgeProgramTable(
                table, &why),
        why);
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    BOOST_CHECK_EQUAL(table.current_width, 16U);
    BOOST_CHECK_EQUAL(table.programs.size(), 10U);
    const auto manifest =
        rl::BuildRelationLocalShardManifestV1(
            table, 256);
    BOOST_REQUIRE_MESSAGE(manifest.valid, manifest.note);
    BOOST_CHECK_EQUAL(manifest.shards.size(), 1U);
    BOOST_CHECK_EQUAL(
        manifest.cost.leaf_receipt_count, 1U);
    std::set<uint32_t> support;
    for (const auto& item : manifest.supports) {
        support.insert(
            item.global_columns.begin(),
            item.global_columns.end());
    }
    BOOST_CHECK_EQUAL(support.size(), 10U);

    std::vector<gf::Fp3> current(
        table.current_width, gf::Fp3::Zero());
    std::vector<gf::Fp3> next = current;
    current[5] = gf::FromSigned3(-1);
    current[6] = gf::FromU64_3(255);
    for (uint32_t bit = 0; bit < 8; ++bit) {
        current[7 + bit] = gf::Fp3::One();
    }
    next = current;
    for (const auto& program : table.programs) {
        gf::Fp3 result;
        BOOST_REQUIRE(cb::EvaluateProgram(
            program, current, next, result, &why));
        BOOST_CHECK(gf::IsZero(result));
    }

    auto changed = current;
    changed[14] = gf::Fp3::Zero();
    bool rejected = false;
    for (const auto& program : table.programs) {
        gf::Fp3 result;
        BOOST_REQUIRE(cb::EvaluateProgram(
            program, changed, next, result, &why));
        rejected |= !gf::IsZero(result);
    }
    BOOST_CHECK(rejected);
}

BOOST_AUTO_TEST_SUITE_END()
