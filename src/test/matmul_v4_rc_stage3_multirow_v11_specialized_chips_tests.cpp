// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_specialized_chips.h>

namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips {
namespace {

cb::ProgramTable GenericTable()
{
    cb::ProgramTable table;
    np::ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        np::BuildCanonicalProgramTableV1(
            table, &manifest, &why),
        why);
    return table;
}

std::array<alg_hash::State, kVerifierQueriesV1>
PoseidonInputs()
{
    std::array<
        alg_hash::State,
        kVerifierQueriesV1> out{};
    for (uint32_t query = 0;
         query < kVerifierQueriesV1;
         ++query) {
        for (uint32_t lane = 0;
             lane < alg_hash::kAlgHashT;
             ++lane) {
            out[query][lane] =
                gf::FromU64(
                    UINT64_C(0x1234567) +
                    UINT64_C(0x10001) * query +
                    UINT64_C(0x101) * lane);
        }
    }
    return out;
}

std::array<alg_hash::State, kVerifierQueriesV1>
PoseidonOutputs(
    const std::array<
        alg_hash::State,
        kVerifierQueriesV1>& inputs)
{
    auto out = inputs;
    for (auto& state : out) {
        alg_hash::Permute(state);
    }
    return out;
}

std::array<
    std::array<
        CanonicalSplitInputV1,
        kCanonicalSplitsV1>,
    kVerifierQueriesV1>
SplitInputs()
{
    std::array<
        std::array<
            CanonicalSplitInputV1,
            kCanonicalSplitsV1>,
        kVerifierQueriesV1> out{};
    for (uint32_t query = 0;
         query < kVerifierQueriesV1;
         ++query) {
        for (uint32_t split = 0;
             split < kCanonicalSplitsV1;
             ++split) {
            uint64_t raw =
                UINT64_C(0x102030405) +
                UINT64_C(0x1000003) * query +
                UINT64_C(0x10007) * split;
            if (query == 0 && split == 0) {
                raw = 0;
            }
            if (query == 0 && split == 1) {
                raw = gf::kP - 1;
            }
            out[query][split] = {
                .raw = raw,
                .expected =
                    split <
                        pj::kPublicFieldSlotsV1
                    ? raw
                    : 0,
                .active = true,
                .expected_is_public =
                    split <
                    pj::kPublicFieldSlotsV1,
            };
        }
    }
    return out;
}

uint64_t GenericPublicSplitViolations(
    const cb::ProgramTable& generic,
    uint64_t raw)
{
    const auto layout =
        pj::CanonicalLayoutV1();
    const auto split =
        layout.public_field[0];
    std::vector<gf::Fp3> current(
        generic.current_width,
        gf::Fp3::Zero());
    std::vector<gf::Fp3> next =
        current;
    const uint32_t low =
        static_cast<uint32_t>(raw);
    const uint32_t high =
        static_cast<uint32_t>(raw >> 32);
    current[split.active] =
        gf::Fp3::One();
    current[split.claim_lo] =
        gf::Fp3::FromFp(gf::FromU64(low));
    current[split.claim_hi] =
        gf::Fp3::FromFp(gf::FromU64(high));
    current[split.expected_lo] =
        current[split.claim_lo];
    current[split.expected_hi] =
        current[split.claim_hi];
    current[
        layout.replay.DigestClaim(0)] =
        gf::Fp3::FromFp(gf::FromU64(raw));
    for (uint32_t bit = 0;
         bit < pj::kRawBitsV1;
         ++bit) {
        current[split.Bit(bit)] =
            ((raw >> bit) & 1U) != 0
            ? gf::Fp3::One()
            : gf::Fp3::Zero();
    }
    bool high_and = true;
    for (uint32_t bit = 0;
         bit < pj::kHighAndBitsV1;
         ++bit) {
        high_and =
            high_and &&
            ((raw >> (32 + bit)) & 1U) != 0;
        current[split.HighAnd(bit)] =
            high_and
            ? gf::Fp3::One()
            : gf::Fp3::Zero();
    }
    current[split.low_nonzero] =
        low != 0
        ? gf::Fp3::One()
        : gf::Fp3::Zero();
    current[split.low_inverse] =
        low != 0
        ? gf::Inv(current[split.claim_lo])
        : gf::Fp3::Zero();

    constexpr uint32_t parent_first =
        np::kPoseidonProgramsV1 +
        np::kTranscriptGlueProgramsV1;
    constexpr uint32_t split_first =
        parent_first +
        pj::kPublicAbsorbSlotsV1 * 3;
    uint64_t violations = 0;
    for (uint32_t ordinal = split_first;
         ordinal < split_first + 106;
         ++ordinal) {
        gf::Fp3 result{};
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            cb::EvaluateProgram(
                generic.programs[ordinal],
                current, next, result, &why),
            why);
        if (!gf::IsZero(result)) {
            ++violations;
        }
    }
    return violations;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_specialized_chips_tests)

BOOST_AUTO_TEST_CASE(
    poseidon_dataflow_substitution_eliminates_only_private_witness_cells)
{
    const auto generic = GenericTable();
    const auto audit =
        AuditPoseidonSubstitutionDataflowV1(
            generic);
    BOOST_REQUIRE_MESSAGE(
        audit.substitution_dataflow_precondition,
        audit.note);
    BOOST_CHECK_EQUAL(audit.generic_programs, 472U);
    BOOST_CHECK_EQUAL(
        audit.generic_instructions, 17412U);
    BOOST_CHECK_EQUAL(
        audit.generic_poseidon_columns, 484U);
    BOOST_CHECK_EQUAL(
        audit.boundary_input_columns, 12U);
    BOOST_CHECK_EQUAL(
        audit.boundary_output_columns, 12U);
    BOOST_CHECK_EQUAL(
        audit.eliminated_internal_columns, 460U);
    BOOST_CHECK_EQUAL(
        audit.distinct_external_poseidon_columns,
        24U);
    BOOST_CHECK_EQUAL(
        audit.forbidden_internal_references, 0U);
    BOOST_CHECK(
        audit.only_inputs_and_final_outputs_escape);
    BOOST_CHECK(
        audit.no_auxiliary_column_escapes);
}

BOOST_AUTO_TEST_CASE(
    round_serial_poseidon_is_differentially_exact_to_native_constraints)
{
    const auto inputs = PoseidonInputs();
    const auto outputs =
        PoseidonOutputs(inputs);
    const auto product =
        BuildPoseidonRoundProductV1(
            inputs, outputs);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    BOOST_CHECK(product.exact_native_outputs);
    BOOST_CHECK(
        product.exact_round_schedule_root_pinned);
    BOOST_CHECK(product.executable);
    BOOST_CHECK_EQUAL(product.trace_rows, 2048U);
    BOOST_CHECK_EQUAL(product.active_rows, 1920U);
    BOOST_CHECK_EQUAL(
        product.scheduler_reserve_rows, 128U);
    BOOST_CHECK_EQUAL(product.trace_columns, 424U);
    BOOST_CHECK_EQUAL(product.programs, 108U);
    BOOST_CHECK_EQUAL(product.instructions, 1668U);
    BOOST_CHECK_LE(product.max_degree, 3U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(!product.recursive_authority_ready);

    const auto native_constraints =
        pa::BuildFixedConstraints(
            pa::CanonicalLayout());
    for (uint32_t query = 0;
         query < kVerifierQueriesV1;
         ++query) {
        const auto witness =
            pa::BuildWitness(
                pa::CanonicalLayout(),
                inputs[query]);
        BOOST_CHECK(
            witness.output == outputs[query]);
        for (const auto& constraint :
             native_constraints) {
            BOOST_CHECK(
                gf::IsZero(
                    constraint.eval(
                        witness.row,
                        witness.row)));
        }
    }
}

BOOST_AUTO_TEST_CASE(
    poseidon_intermediate_output_and_schedule_forgeries_are_rejected)
{
    const auto inputs = PoseidonInputs();
    const auto outputs =
        PoseidonOutputs(inputs);
    const auto product =
        BuildPoseidonRoundProductV1(
            inputs, outputs);
    BOOST_REQUIRE(product.valid);

    auto forged = product.columns;
    forged[product.layout.x4[7]][41] =
        gf::Add(
            forged[product.layout.x4[7]][41],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(
            product.cs, forged,
            product.preprocessed_columns,
            product.preprocessed_row_group_root),
        0U);

    auto bad_outputs = outputs;
    bad_outputs[3][4] =
        gf::Add(bad_outputs[3][4], 1);
    const auto bad_product =
        BuildPoseidonRoundProductV1(
            inputs, bad_outputs);
    BOOST_CHECK(!bad_product.valid);
    BOOST_CHECK_GT(bad_product.violations, 0U);

    forged = product.columns;
    const uint32_t schedule_col =
        product.layout.round_constant[0];
    forged[schedule_col][8] =
        gf::Add(
            forged[schedule_col][8],
            gf::Fp3::One());
    BOOST_CHECK_GT(
        RecountViolationsV1(
            product.cs, forged,
            product.preprocessed_columns,
            product.preprocessed_row_group_root),
        0U);
}

BOOST_AUTO_TEST_CASE(
    row_serial_u64_matches_generic_split_and_rejects_goldilocks_alias)
{
    const auto generic = GenericTable();
    auto inputs = SplitInputs();
    const auto product =
        BuildCanonicalSplitProductV1(inputs);
    BOOST_REQUIRE_MESSAGE(
        product.valid, product.note);
    BOOST_CHECK(product.exact_seven_split_schedule);
    BOOST_CHECK(product.goldilocks_alias_rejected);
    BOOST_CHECK(product.exact_schedule_root_pinned);
    BOOST_CHECK(product.executable);
    BOOST_CHECK_EQUAL(product.trace_rows, 32768U);
    BOOST_CHECK_EQUAL(product.active_rows, 28672U);
    BOOST_CHECK_EQUAL(
        product.scheduler_reserve_rows, 4096U);
    BOOST_CHECK_EQUAL(product.trace_columns, 26U);
    BOOST_CHECK_EQUAL(product.programs, 27U);
    BOOST_CHECK_EQUAL(product.instructions, 162U);
    BOOST_CHECK_LE(product.max_degree, 4U);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(
        GenericPublicSplitViolations(
            generic, gf::kP - 1),
        0U);

    constexpr uint64_t alias = gf::kP + 5;
    BOOST_CHECK_GT(
        GenericPublicSplitViolations(
            generic, alias),
        0U);
    inputs[0][0].raw = alias;
    inputs[0][0].expected = alias;
    const auto rejected =
        BuildCanonicalSplitProductV1(inputs);
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK_GT(rejected.violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    exact_specialized_inventory_fits_one_fixedpoint_partition)
{
    const auto generic = GenericTable();
    cb::ProgramTable poseidon;
    cb::ProgramTable split;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildPoseidonRoundProgramTableV1(
            poseidon, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        BuildCanonicalSplitProgramTableV1(
            split, &why),
        why);
    const auto audit =
        AssessSpecializedCostV1(
            generic, poseidon, split);
    BOOST_REQUIRE_MESSAGE(
        audit.valid_foundation, audit.note);
    BOOST_CHECK_EQUAL(
        audit.generic_total_instructions,
        23669U);
    BOOST_CHECK_EQUAL(
        audit.generic_poseidon_instructions,
        17412U);
    BOOST_CHECK_EQUAL(
        audit.generic_transcript_instructions,
        1098U);
    BOOST_CHECK_EQUAL(
        audit.generic_unrolled_split_instructions,
        4972U);
    BOOST_CHECK_EQUAL(
        audit.retained_parent_instructions,
        187U);
    BOOST_CHECK_EQUAL(
        audit.specialized_poseidon_instructions,
        1668U);
    BOOST_CHECK_EQUAL(
        audit.specialized_split_instructions,
        162U);
    BOOST_CHECK_EQUAL(
        audit.specialized_total_instructions,
        3115U);
    BOOST_CHECK_EQUAL(
        audit.fixedpoint_instruction_cap,
        4160U);
    BOOST_CHECK_EQUAL(
        audit.instruction_headroom, 1045U);
    BOOST_CHECK_EQUAL(
        audit.generic_relation_shards, 6U);
    BOOST_CHECK_EQUAL(
        audit.specialized_relation_shards, 1U);
    BOOST_CHECK(
        audit.specialized_cost_below_fixedpoint_cap);
    BOOST_CHECK(
        audit.generic_fallback_preserved);
    BOOST_CHECK(
        !audit.specialized_recursive_receipt_consumption_executed);
    BOOST_CHECK(!audit.recursive_authority_ready);
    BOOST_TEST_MESSAGE(
        "V11_SPECIALIZED_FIXEDPOINT generic=23669"
        " minus_poseidon=17412"
        " minus_unrolled_split=4972"
        " plus_round_poseidon=1668"
        " plus_row_split=162"
        " total=3115 cap=4160 headroom=1045"
        " generic_fallback_shards=6"
        " specialized_partitions=1"
        " receipt_consumption=0 authority=0");
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_specialized_chips
