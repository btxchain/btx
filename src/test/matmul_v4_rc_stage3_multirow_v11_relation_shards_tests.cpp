// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_relation_shards.h>

#include <algorithm>

namespace matmul::v4::rc::stage3_multirow_v11_relation_shards {
namespace {

using gf::Fp3;

struct Fixture {
    cb::ProgramTable full;
    np::ManifestV1 manifest;
    PlanV1 plan;
};

Fixture MakeFixture()
{
    Fixture out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        np::BuildCanonicalProgramTableV1(
            out.full, &out.manifest, &why),
        why);
    out.plan = BuildPlanV1(out.full);
    return out;
}

uint64_t NextRandom(uint64_t& state)
{
    state += UINT64_C(0x9e3779b97f4a7c15);
    uint64_t z = state;
    z = (z ^ (z >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94d049bb133111eb);
    return z ^ (z >> 31);
}

bool DigestEq(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return false;
    }
    return true;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_relation_shards_tests)

BOOST_AUTO_TEST_CASE(
    exact_six_relation_by_two_q96_plan_and_q64_fallback_close)
{
    const auto fixture = MakeFixture();
    const auto& plan = fixture.plan;
    BOOST_REQUIRE_MESSAGE(plan.valid_foundation, plan.note);
    BOOST_CHECK_EQUAL(plan.full_programs, 1276U);
    BOOST_CHECK_EQUAL(plan.full_instructions, 23669U);
    BOOST_CHECK_EQUAL(plan.query_shards, 2U);
    BOOST_CHECK_EQUAL(plan.queries_per_query_shard, 96U);
    BOOST_CHECK_EQUAL(plan.leaf_receipts, 12U);
    BOOST_CHECK_EQUAL(plan.fallback_query_shards, 3U);
    BOOST_CHECK_EQUAL(plan.fallback_queries_per_query_shard, 64U);
    BOOST_CHECK_EQUAL(plan.fallback_leaf_receipts, 18U);
    BOOST_CHECK(plan.q96_exact_partition_of_one_q192_transcript);
    BOOST_CHECK(!plan.q96_independent_lanes);
    BOOST_CHECK(!plan.q96_soundness_multiplication_claimed);
    BOOST_CHECK(plan.every_relation_shard_executable);
    BOOST_CHECK(plan.exact_program_reassembly);
    BOOST_CHECK(plan.manifest_poseidon_bound);
    BOOST_CHECK(plan.symbolic_composition.valid);
    BOOST_CHECK(plan.symbolic_composition.exact_disjoint_partition);
    BOOST_CHECK(
        plan.symbolic_composition.coefficientwise_lambda_identity);
    BOOST_CHECK(plan.symbolic_composition.quotient_sum_identity);
    BOOST_CHECK_EQUAL(plan.symbolic_composition.missing_terms, 0U);
    BOOST_CHECK_EQUAL(plan.symbolic_composition.duplicate_terms, 0U);
    BOOST_CHECK_EQUAL(
        plan.symbolic_composition.wrong_lambda_exponents, 0U);
    std::vector<gf::Fp> manifest_preimage;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildManifestPreimageV1(
            fixture.full, plan.shards,
            manifest_preimage, &why),
        why);
    BOOST_CHECK(!manifest_preimage.empty());
    for (const auto lane : manifest_preimage) {
        BOOST_CHECK_LT(lane, gf::kP);
    }
    uint64_t total_instructions = 0;
    uint32_t total_programs = 0;
    for (const auto& shard : plan.shards) {
        BOOST_CHECK(shard.valid);
        BOOST_CHECK(shard.program_boundary_exact);
        BOOST_CHECK(shard.register_dependencies_local);
        BOOST_CHECK_LE(
            shard.instruction_count,
            uint64_t{np::kFixedPointInstructionCapV1});
        BOOST_CHECK_LE(shard.q64_trace_rows, 1U << 20);
        BOOST_CHECK_LE(shard.q64_lde_rows, 1U << 24);
        BOOST_CHECK_LE(shard.q96_trace_rows, 1U << 20);
        BOOST_CHECK_LE(shard.q96_lde_rows, 1U << 24);
        total_instructions += shard.instruction_count;
        total_programs += shard.program_count;
        BOOST_TEST_MESSAGE(
            "V11_RELATION_SHARD ordinal=" << shard.ordinal
            << " range=[" << shard.first_program << ","
            << shard.first_program + shard.program_count << ")"
            << " programs=" << shard.program_count
            << " instructions=" << shard.instruction_count
            << " real_rows=" << shard.q64_real_rows
            << " trace_rows=" << shard.q64_trace_rows
            << " lde_rows=" << shard.q64_lde_rows
            << " q96_real_rows=" << shard.q96_real_rows
            << " q96_trace_rows=" << shard.q96_trace_rows
            << " q96_lde_rows=" << shard.q96_lde_rows);
    }
    BOOST_CHECK_EQUAL(total_instructions, plan.full_instructions);
    BOOST_CHECK_EQUAL(total_programs, plan.full_programs);
    BOOST_CHECK(
        plan.residual_mask & kResidualRecursiveLeafReceipts);
    BOOST_CHECK(
        plan.residual_mask & kResidualRecursiveQuotientJoin);
    BOOST_CHECK(!plan.recursive_leaf_receipts_verified);
    BOOST_CHECK(!plan.recursive_quotient_join_executed);
    BOOST_CHECK(!plan.recursive_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    symbolic_global_lambda_exponents_and_quotient_sum_recompose)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.plan.valid_foundation);
    uint64_t state = UINT64_C(0x8a1432d09f55b701);
    for (uint32_t probe = 0; probe < 8; ++probe) {
        std::vector<Fp3> residuals(fixture.plan.full_programs);
        std::vector<Fp3> selectors(fixture.plan.full_programs);
        for (uint32_t i = 0; i < residuals.size(); ++i) {
            residuals[i] = Fp3{
                gf::FromU64(NextRandom(state)),
                gf::FromU64(NextRandom(state)),
                gf::FromU64(NextRandom(state))};
            selectors[i] =
                ((i + probe) % 5) == 0
                ? Fp3::Zero() : Fp3::One();
        }
        const Fp3 lambda{
            gf::FromU64(NextRandom(state)),
            gf::FromU64(NextRandom(state)),
            gf::FromU64(NextRandom(state))};
        Fp3 zh{
            gf::FromU64(NextRandom(state)),
            gf::FromU64(NextRandom(state)),
            gf::FromU64(NextRandom(state))};
        if (gf::IsZero(zh)) zh = Fp3::One();
        const auto evaluated = EvaluateCompositionV1(
            fixture.plan, residuals, selectors, lambda, zh);
        BOOST_REQUIRE(evaluated.input_shape_exact);
        BOOST_CHECK(evaluated.partial_sum_matches);
        BOOST_CHECK(evaluated.quotient_sum_matches);
        BOOST_CHECK(evaluated.valid);
    }
}

BOOST_AUTO_TEST_CASE(
    omission_overlap_reorder_and_local_program_mutation_reject)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.plan.valid_foundation);

    auto omitted = fixture.plan;
    omitted.shards[5].local_table.programs.pop_back();
    --omitted.shards[5].program_count;
    BOOST_CHECK(!ReassemblesExactlyV1(fixture.full, omitted));

    auto overlap = fixture.plan;
    --overlap.shards[2].first_program;
    --overlap.shards[2].first_lambda_exponent;
    BOOST_CHECK(!ReassemblesExactlyV1(fixture.full, overlap));

    auto reordered = fixture.plan;
    std::swap(reordered.shards[0], reordered.shards[1]);
    BOOST_CHECK(!ReassemblesExactlyV1(fixture.full, reordered));

    auto mutated = fixture.plan;
    bool changed = false;
    for (auto& program : mutated.shards[0].local_table.programs) {
        for (auto& instruction : program.instructions) {
            if (instruction.opcode == cb::Opcode::Add) {
                instruction.opcode = cb::Opcode::Sub;
                changed = true;
                break;
            }
        }
        if (changed) break;
    }
    BOOST_REQUIRE(changed);
    BOOST_CHECK(!ReassemblesExactlyV1(fixture.full, mutated));
    const auto recomputed_local_root =
        cb::CommitProgramTableAlgHash(
            mutated.shards[0].local_table);
    BOOST_CHECK(!DigestEq(
        recomputed_local_root,
        fixture.plan.shards[0].local_program_root));
    mutated.shards[0].local_program_root =
        recomputed_local_root;
    const auto mutated_root = ComputeManifestRootV1(
        fixture.full, mutated.shards);
    BOOST_CHECK(!DigestEq(
        fixture.plan.shard_manifest_root, mutated_root));
}

BOOST_AUTO_TEST_CASE(
    manifest_root_range_root_and_instruction_cap_attacks_reject)
{
    const auto fixture = MakeFixture();
    BOOST_REQUIRE(fixture.plan.valid_foundation);

    auto range = fixture.plan.shards;
    ++range[1].first_lambda_exponent;
    BOOST_CHECK(!DigestEq(
        fixture.plan.shard_manifest_root,
        ComputeManifestRootV1(fixture.full, range)));

    auto local_root = fixture.plan.shards;
    local_root[3].local_program_root[0] =
        gf::Add(
            local_root[3].local_program_root[0],
            gf::FromU64(1));
    BOOST_CHECK(!DigestEq(
        fixture.plan.shard_manifest_root,
        ComputeManifestRootV1(fixture.full, local_root)));

    auto raw_alias = fixture.plan.shards;
    bool alias_written = false;
    for (auto& shard : raw_alias) {
        for (auto& program : shard.local_table.programs) {
            for (auto& instruction : program.instructions) {
                if (instruction.opcode == cb::Opcode::Constant &&
                    gf::IsZero(instruction.constant)) {
                    instruction.constant.c0 = gf::kP;
                    alias_written = true;
                    break;
                }
            }
            if (alias_written) break;
        }
        if (alias_written) break;
    }
    BOOST_REQUIRE(alias_written);
    for (auto& shard : raw_alias) {
        shard.local_program_root =
            cb::CommitProgramTableAlgHash(shard.local_table);
    }
    std::vector<gf::Fp> rejected_preimage;
    BOOST_CHECK(!BuildManifestPreimageV1(
        fixture.full, raw_alias, rejected_preimage));

    auto cap_plus_one = fixture.full;
    // Six shards are forced by total cost. Appending a 4,161-instruction
    // single program creates a relation that no legal boundary can contain.
    cb::Program huge;
    huge.version = cb::kConstraintBytecodeVersion;
    huge.role = cap_plus_one.role;
    huge.constraint_ordinal =
        static_cast<uint32_t>(cap_plus_one.programs.size());
    huge.kind = air_quotient::AirKind::kEverywhere;
    huge.current_width = cap_plus_one.current_width;
    huge.next_width = cap_plus_one.next_width;
    huge.challenge_width = 0;
    // A live addition chain: one constant followed by 4,160 additions of the
    // previous register with itself. Declared degree stays zero, so append one
    // current load and final add to make degree one while retaining all nodes.
    cb::Instruction zero;
    zero.opcode = cb::Opcode::Constant;
    huge.instructions.push_back(zero);
    for (uint32_t i = 1;
         i + 1 < np::kFixedPointInstructionCapV1; ++i) {
        cb::Instruction add;
        add.opcode = cb::Opcode::Add;
        add.lhs = i - 1;
        add.rhs = i - 1;
        huge.instructions.push_back(add);
    }
    cb::Instruction load;
    load.opcode = cb::Opcode::Current;
    load.lhs = 0;
    huge.instructions.push_back(load);
    cb::Instruction final_add;
    final_add.opcode = cb::Opcode::Add;
    final_add.lhs = np::kFixedPointInstructionCapV1 - 2;
    final_add.rhs = np::kFixedPointInstructionCapV1 - 1;
    huge.instructions.push_back(final_add);
    huge.declared_degree = 1;
    BOOST_REQUIRE_EQUAL(
        huge.instructions.size(),
        np::kFixedPointInstructionCapV1 + 1);
    cap_plus_one.programs.push_back(std::move(huge));
    BOOST_REQUIRE(cb::ValidateProgramTable(cap_plus_one));
    const auto rejected = BuildPlanV1(cap_plus_one);
    BOOST_CHECK(!rejected.valid_foundation);
    BOOST_CHECK(
        rejected.residual_mask &
        kResidualFullProgramInvalid);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_relation_shards
