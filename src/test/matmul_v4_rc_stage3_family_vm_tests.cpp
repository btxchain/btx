// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_family_vm.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

namespace {

namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace vm =
    matmul::v4::rc::stage3_family_vm;
namespace aq =
    matmul::v4::rc::air_quotient;
namespace gf =
    matmul::v4::rc::gkr_field;

cb::ProgramTable SmallExecutableTable()
{
    using Op = cb::Opcode;
    cb::ProgramTable table;
    table.role =
        matmul::v4::rc::RCStage3RelationRole::
            EpisodeDeterministicBuilder;
    table.current_width = 1;
    table.next_width = 1;
    const auto append =
        [&](aq::AirKind kind,
            std::vector<cb::Instruction> code) {
            cb::Program program;
            program.role = table.role;
            program.constraint_ordinal =
                static_cast<uint32_t>(
                    table.programs.size());
            program.kind = kind;
            program.declared_degree = 1;
            program.current_width = 1;
            program.next_width = 1;
            program.instructions =
                std::move(code);
            table.programs.push_back(
                std::move(program));
        };
    const auto z = gf::Fp3::Zero();
    append(
        aq::AirKind::kEverywhere,
        {{Op::Current, 0, 0, z},
         {Op::Constant, 0, 0,
          gf::FromU64_3(7)},
         {Op::Sub, 0, 1, z}});
    append(
        aq::AirKind::kTransition,
        {{Op::Next, 0, 0, z},
         {Op::Current, 0, 0, z},
         {Op::Sub, 0, 1, z}});
    append(
        aq::AirKind::kEverywhere,
        {{Op::Current, 0, 0, z},
         {Op::Constant, 0, 0, z},
         {Op::Add, 0, 1, z},
         {Op::Current, 0, 0, z},
         {Op::Sub, 2, 3, z}});
    append(
        aq::AirKind::kEverywhere,
        {{Op::Current, 0, 0, z},
         {Op::Constant, 0, 0,
          gf::Fp3::One()},
         {Op::Mul, 0, 1, z},
         {Op::Current, 0, 0, z},
         {Op::Sub, 2, 3, z}});
    return table;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_family_vm_tests)

BOOST_AUTO_TEST_CASE(
    pow_bytecode_verticalizes_width_with_exact_multisets)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        matmul::v4::rc::
            BuildRCStage3EpisodePowProgramTable(
                table, &why));
    const auto plan =
        vm::BuildFamilyVmPlanV1(table, 32);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    BOOST_CHECK(plan.canonical_program_table);
    BOOST_CHECK(plan.exact_row_program_pc_schedule);
    BOOST_CHECK(plan.cyclic_next_row_semantics);
    BOOST_CHECK(plan.source_read_multiset_balanced);
    BOOST_CHECK(plan.register_read_multiset_balanced);
    BOOST_CHECK(plan.register_key_encoding_injective);
    BOOST_CHECK(plan.selector_terminal_schedule_exact);
    BOOST_CHECK(plan.dual_lanes_after_r0);
    BOOST_CHECK(plan.fixed_width_under_512);
    BOOST_CHECK_EQUAL(
        plan.physical_columns, 193U);
    BOOST_CHECK_EQUAL(
        plan.direct_query_value_bytes, 889344U);
    BOOST_CHECK_EQUAL(
        plan.terminal_checks,
        11U * 32U + 31U + 1U + 1U);
    BOOST_CHECK(
        !plan.split_rap_family_proof_executable);
    BOOST_CHECK(
        !plan.production_authority_ready);
    BOOST_CHECK(
        vm::ValidateFamilyVmPlanV1(
            table, plan, &why));
}

BOOST_AUTO_TEST_CASE(
    plan_mutation_and_non_power_of_two_rows_reject)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE(
        matmul::v4::rc::
            BuildRCStage3ExtractMixProgramTable(
                matmul::v4::rc::
                    RCStage3RelationRole::
                        EpisodeExtract,
                table, &why));
    const auto plan =
        vm::BuildFamilyVmPlanV1(table, 8);
    BOOST_REQUIRE_MESSAGE(plan.valid, plan.note);
    {
        auto bad = plan;
        ++bad.source_load_multiplicity[0];
        BOOST_CHECK(
            !vm::ValidateFamilyVmPlanV1(
                table, bad, &why));
    }
    {
        auto bad = plan;
        --bad.padded_vertical_rows;
        BOOST_CHECK(
            !vm::ValidateFamilyVmPlanV1(
                table, bad, &why));
    }
    BOOST_CHECK(
        !vm::BuildFamilyVmPlanV1(
             table, 7).valid);
}

BOOST_AUTO_TEST_CASE(
    executable_vertical_vm_split_rap_roundtrip_and_mutations)
{
    const cb::ProgramTable table =
        SmallExecutableTable();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(table, &why),
        why);
    const auto plan =
        vm::BuildFamilyVmPlanV1(table, 4);
    BOOST_REQUIRE(plan.valid);
    BOOST_REQUIRE(plan.fits_single_split_rap);
    BOOST_CHECK_EQUAL(
        plan.padded_vertical_rows, 128U);
    BOOST_CHECK_EQUAL(
        plan.minimum_vm_segments, 1U);

    const std::vector<std::vector<gf::Fp3>>
        source{
            std::vector<gf::Fp3>(
                4, gf::FromU64_3(7))};
    const uint256 statement =
        uint256::ONE;
    const uint256 seed = uint256::ONE;
    const uint256 registry_root =
        uint256::ONE;
    const auto proved =
        vm::ProveFamilyVmV1(
            table, source, 7, registry_root,
            statement, seed);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    std::vector<unsigned char> wire;
    BOOST_REQUIRE(
        vm::SerializeFamilyVmProofV1(
            proved.proof, wire) > 0);
    const auto decoded =
        vm::DeserializeFamilyVmProofV1(wire);
    BOOST_REQUIRE(decoded.has_value());
    const auto audit =
        vm::VerifyFamilyVmV1(
            table, proved.public_inputs,
            *decoded, seed);
    BOOST_REQUIRE_MESSAGE(
        audit.valid, audit.note);
    BOOST_CHECK(
        audit.canonical_program_table_root_pinned);
    BOOST_CHECK(
        audit.program_selection_bound_in_transcript);
    BOOST_CHECK(
        !audit.registry_membership_proved);
    BOOST_CHECK(
        audit.exact_row_program_pc_schedule);
    BOOST_CHECK(
        audit.program_fetch_metadata_logup_pinned);
    BOOST_CHECK(
        audit.source_multiplicity_consensus_u32);
    BOOST_CHECK(
        audit.register_multiplicity_consensus_u32);
    BOOST_CHECK(
        audit.cyclic_current_next_all_rows);
    BOOST_CHECK(
        audit.dual_lookup_challenges_after_phase0);
    BOOST_CHECK(
        audit.phase0_group_root_exact);
    BOOST_CHECK(
        audit.split_rap_quotient_fri_verified);
    BOOST_CHECK(
        !audit.verifier_rebuilds_full_preprocessed_schedule);
    BOOST_CHECK(
        audit.sublinear_verifier);
    BOOST_CHECK_EQUAL(
        audit.verifier_work_rows,
        1U + 16U + vm::kFamilyVmQueriesV1);
    BOOST_CHECK(
        !audit.unsegmented_residual_fold_required);
    BOOST_CHECK(
        !audit.segmented_family_fold_executable);
    BOOST_CHECK(
        !audit.production_authority_ready);
    const auto resolved =
        vm::VerifyFamilyVmResolvedV1(
            proved.public_inputs,
            proved.proof, seed,
            [table](
                const uint256& root,
                uint32_t program_id,
                cb::ProgramTable& selected) {
                if (root != uint256::ONE ||
                    program_id != 7) {
                    return false;
                }
                selected = table;
                return true;
            });
    BOOST_REQUIRE(resolved.valid);
    BOOST_CHECK(
        resolved.registry_membership_proved);
    BOOST_CHECK(
        !vm::VerifyFamilyVmResolvedV1(
             proved.public_inputs,
             proved.proof, seed,
             [](const uint256&, uint32_t,
                cb::ProgramTable&) {
                 return false;
             }).valid);

    {
        auto bad_wire = wire;
        bad_wire.back() ^= 1;
        const auto bad_decoded =
            vm::DeserializeFamilyVmProofV1(
                bad_wire);
        BOOST_REQUIRE(
            bad_decoded.has_value());
        BOOST_CHECK(
            !vm::VerifyFamilyVmV1(
                 table, proved.public_inputs,
                 *bad_decoded, seed).valid);
    }
    {
        auto bad = proved.proof;
        bad.lookup_challenges.alpha1 =
            gf::Add(
                bad.lookup_challenges.alpha1,
                gf::Fp3::One());
        BOOST_CHECK(
            !vm::VerifyFamilyVmV1(
                 table, proved.public_inputs,
                 bad, seed).valid);
    }
    {
        auto bad = proved.public_inputs;
        bad.phase0_row_group_root =
            uint256::ONE;
        BOOST_CHECK(
            !vm::VerifyFamilyVmV1(
                 table, bad, proved.proof,
                 seed).valid);
    }
    {
        auto bad_table = table;
        bad_table.programs[0]
            .instructions[1].constant =
            gf::FromU64_3(8);
        BOOST_CHECK(
            !vm::VerifyFamilyVmV1(
                 bad_table,
                 proved.public_inputs,
                 proved.proof, seed).valid);
    }

    auto false_source = source;
    false_source[0][2] =
        gf::FromU64_3(8);
    BOOST_CHECK(
        !vm::ProveFamilyVmV1(
             table, false_source, 7,
             registry_root,
             statement, seed).ok);
}

BOOST_AUTO_TEST_CASE(
    verifier_work_is_independent_of_vertical_trace_rows)
{
    const cb::ProgramTable table =
        SmallExecutableTable();
    const auto small =
        vm::EstimateFamilyVmVerifierWorkV1(
            table, 4);
    const auto large =
        vm::EstimateFamilyVmVerifierWorkV1(
            table, 1U << 23);
    BOOST_REQUIRE(small.valid);
    BOOST_REQUIRE(large.valid);
    BOOST_CHECK(
        !small.materializes_vertical_schedule);
    BOOST_CHECK(
        !large.materializes_vertical_schedule);
    BOOST_CHECK(
        large.asymptotically_sublinear);
    BOOST_CHECK_EQUAL(
        small.verifier_work_rows,
        large.verifier_work_rows);
    BOOST_CHECK_EQUAL(
        small.verifier_work_cells,
        large.verifier_work_cells);
    BOOST_CHECK_GT(
        large.vertical_trace_rows,
        small.vertical_trace_rows *
            1000000U);
    BOOST_CHECK_EQUAL(
        large.vertical_trace_rows,
        vm::kFamilyVmCoefficientCapV1);
}

BOOST_AUTO_TEST_SUITE_END()
