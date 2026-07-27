// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_fixedpoint.h>

namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint {
namespace {

cb::ProgramTable ParentTable(uint32_t instructions)
{
    cb::Program program;
    program.role = RCStage3RelationRole::CompositionLink;
    program.kind = air_quotient::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1298;
    program.next_width = 1298;
    program.instructions.reserve(instructions);
    for (uint32_t i = 0; i < instructions; ++i) {
        cb::Instruction instruction;
        if (i == 0) {
            instruction.opcode = cb::Opcode::Current;
            instruction.lhs = 0;
        } else {
            instruction.opcode = cb::Opcode::Add;
            instruction.lhs = i - 1;
            instruction.rhs = 0;
        }
        program.instructions.push_back(instruction);
    }
    cb::ProgramTable table;
    table.role = program.role;
    table.current_width = program.current_width;
    table.next_width = program.next_width;
    table.programs.push_back(std::move(program));
    return table;
}

ExecutableInventoryV1 Inventory(uint32_t child_width)
{
    ExecutableInventoryV1 out;
    out.child_trace_columns = child_width;
    out.parent_join_columns = 1298;
    out.parent_join_rows = 512;
    out.merkle_hash_columns = 500;
    out.merkle_hash_rows = 256;
    out.merkle_fold_columns = 16;
    out.merkle_fold_rows = 8;
    out.merkle_query_count = 1;
    out.decoder_columns = 27;
    out.decoder_rows = 8192;
    out.deep_vm_columns = 51;
    out.deep_vm_rows = 4096;
    out.deep_vm_real_rows = 3000;
    out.deep_vm_query_count = 1;
    out.deep_vm_instruction_rows = 1276;
    out.recursive_parent_columns = 74;
    out.recursive_parent_rows = 256;
    out.recursive_parent_proof_bytes = 2207844;
    out.recursive_parent_receipt_bytes = 2208636;
    out.recursive_parent_verify_micros = 429611;
    out.every_product_valid = true;
    out.full_query_shards_materialized = false;
    return out;
}

WireMeasurementV1 ParentJoinWire()
{
    WireMeasurementV1 out;
    out.trace_rows = 512;
    out.columns = 1298;
    // The external full parent-join run reported 13.55 MiB. Round upward so
    // every subsequent headroom calculation is conservative.
    out.proof_bytes =
        (1355ULL * (1ULL << 20) + 99) / 100;
    out.verify_micros = 700000;
    out.proof_bytes_evidence = EvidenceClassV1::Measured;
    out.verify_evidence = EvidenceClassV1::Measured;
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_fixedpoint_tests)

BOOST_AUTO_TEST_CASE(
    opaque_callbacks_fail_closed_and_exact_instruction_cap_is_4160)
{
    const auto opaque =
        AssessCanonicalVmBudgetV1(1298, nullptr);
    BOOST_CHECK_EQUAL(
        opaque.max_instructions_under_lde_cap, 4160U);
    BOOST_CHECK(!opaque.canonical_table_present);
    BOOST_CHECK(!opaque.exact_instruction_inventory);
    BOOST_CHECK(!opaque.lde_rows_fit);

    const auto narrow_table = ParentTable(2600);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(narrow_table, &why), why);
    const auto narrow =
        AssessCanonicalVmBudgetV1(1298, &narrow_table);
    BOOST_CHECK(narrow.exact_instruction_inventory);
    BOOST_CHECK_EQUAL(narrow.exact_instruction_count, 2600U);
    BOOST_CHECK_EQUAL(
        narrow.exact_real_rows,
        uint64_t{192} * (1298 + 2600 + 3));
    BOOST_CHECK_EQUAL(narrow.trace_rows, 1U << 20);
    BOOST_CHECK_EQUAL(narrow.lde_rows, 1U << 24);
    BOOST_CHECK(narrow.lde_rows_fit);

    const auto too_wide_table = ParentTable(4161);
    BOOST_REQUIRE_MESSAGE(
        cb::ValidateProgramTable(too_wide_table, &why), why);
    const auto too_wide =
        AssessCanonicalVmBudgetV1(1298, &too_wide_table);
    BOOST_CHECK_EQUAL(too_wide.exact_instruction_count, 4161U);
    BOOST_CHECK_EQUAL(too_wide.trace_rows, 1U << 21);
    BOOST_CHECK(!too_wide.trace_rows_fit);
    BOOST_CHECK(!too_wide.lde_rows_fit);
}

BOOST_AUTO_TEST_CASE(
    vertical_width_closes_but_unsharded_binary_rows_do_not)
{
    const auto leaf = Inventory(2);
    const auto parent = Inventory(74);
    const auto table = ParentTable(2600);
    const auto assessed = AssessFixedPointV1(
        leaf, parent, ParentJoinWire(), &table, 2, 32);
    BOOST_CHECK(assessed.vertical_chip_multiplexing);
    BOOST_CHECK_EQUAL(
        assessed.level1.max_chip_columns, 1298U);
    BOOST_CHECK_EQUAL(
        assessed.level1.normalized_columns, 1330U);
    BOOST_CHECK_EQUAL(
        assessed.level2.normalized_columns, 1330U);
    BOOST_CHECK_EQUAL(
        assessed.width_slope_per_child_proof_column, 0U);
    BOOST_CHECK(assessed.width_fixed_point);
    BOOST_CHECK(assessed.level1.columns_fit);
    BOOST_CHECK(assessed.level2.columns_fit);
    BOOST_CHECK(!assessed.level2.lde_fit);
    BOOST_CHECK_GT(assessed.scheduler_columns_headroom, 32U);
    BOOST_CHECK_LT(assessed.scheduler_columns_headroom, 235U);
    BOOST_CHECK_LE(
        assessed.level2.projected_max_proof_bytes,
        kWireBudgetBytesV1);
    BOOST_CHECK(
        assessed.level2.root_verify_within_budget);
    BOOST_CHECK(!assessed.level_two_fits);
    BOOST_CHECK(!assessed.complete_fixed_point);
    BOOST_CHECK(!assessed.aggregation_ready);
    BOOST_CHECK(
        assessed.residual_mask &
        kResidualChildVerifierNotInParentAir);
    BOOST_CHECK(
        assessed.residual_mask &
        kResidualFullQueryShardsNotMaterialized);
    BOOST_CHECK(
        assessed.residual_mask &
        kResidualSemanticCtlNotRecursivelyConsumed);

    BOOST_CHECK(assessed.shard_plan.exact_vm_inventory);
    BOOST_CHECK(
        assessed.shard_plan.queries_per_shard > 0);
    BOOST_CHECK(
        assessed.shard_plan.queries_per_shard <
        abi::kQueryCountV11);
    BOOST_CHECK_GE(assessed.shard_plan.shards_per_child, 2U);
    BOOST_CHECK(
        assessed.shard_plan.covers_q192_exactly);
    BOOST_CHECK(
        assessed.shard_plan.every_shard_lde_fits);
    BOOST_CHECK(
        !assessed.shard_plan.receipt_aggregation_executable);
    BOOST_TEST_MESSAGE(
        "V11 fixed-point: width="
        << assessed.level2.normalized_columns
        << " active_rows="
        << assessed.level2.vertical_active_rows
        << " lde=" << assessed.level2.lde_rows
        << " projected_wire="
        << assessed.level2.projected_max_proof_bytes
        << " scheduler_headroom="
        << assessed.scheduler_columns_headroom
        << " shard_queries="
        << assessed.shard_plan.queries_per_shard
        << " shards_per_child="
        << assessed.shard_plan.shards_per_child
        << " residual=0x" << std::hex
        << assessed.residual_mask << std::dec);
}

BOOST_AUTO_TEST_CASE(
    missing_wire_and_verify_measurements_cannot_close_budget)
{
    const auto inventory = Inventory(74);
    const auto table = ParentTable(1276);
    WireMeasurementV1 missing;
    missing.trace_rows = 512;
    missing.columns = 1298;
    const auto assessed = AssessFixedPointV1(
        inventory, inventory, missing, &table, 1, 32);
    BOOST_CHECK(!assessed.level1.every_wire_proof_fits);
    // The native 74-column root receipt was measured below 900 ms; the
    // missing measurement here is the whole 1,298-column normalized proof.
    BOOST_CHECK(assessed.level1.root_verify_within_budget);
    BOOST_CHECK(
        assessed.residual_mask &
        kResidualWholeRootWireUnmeasured);
    BOOST_CHECK(
        assessed.residual_mask &
        kResidualWholeRootVerifyUnmeasured);
    BOOST_CHECK(!assessed.complete_fixed_point);
}

BOOST_AUTO_TEST_CASE(
    reentry_root_substitution_and_out_of_range_ordinal_reject)
{
    rp::ProductV1 level_one;
    rp::ProductV1 level_two;
    std::array<rp::ChildInputV1,
               rp::kRecursiveParentArityV1> children{};
    const auto invalid = AuditLevelOneToLevelTwoV1(
        level_one, children, level_two, 0);
    BOOST_CHECK(!invalid.valid_foundation);
    BOOST_CHECK(!invalid.recursive_authority_ready);

    level_one.valid = true;
    level_two.valid = true;
    level_one.receipt.parent_proof_root = uint256::ONE;
    level_two.receipt.children[0].proof_wire_root =
        uint256::ZERO;
    const auto substituted = AuditLevelOneToLevelTwoV1(
        level_one, children, level_two, 0);
    BOOST_CHECK(!substituted.exact_parent_proof_payload);
    BOOST_CHECK(!substituted.valid_foundation);

    const auto ordinal = AuditLevelOneToLevelTwoV1(
        level_one, children, level_two,
        rp::kRecursiveParentArityV1);
    BOOST_CHECK(!ordinal.valid_foundation);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_fixedpoint
