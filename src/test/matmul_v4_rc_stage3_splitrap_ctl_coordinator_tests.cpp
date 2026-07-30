// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_splitrap_ctl_coordinator.h>

namespace matmul::v4::rc::splitrap_ctl {
namespace {

namespace gf = gkr_field;
namespace aq = air_quotient;

uint256 Seed(unsigned char byte)
{
    uint256 out;
    out.SetNull();
    out.data()[0] = byte;
    return out;
}

struct Fixture {
    RCStage3CoupledBankDequantPin pin;
    std::vector<std::vector<gf::Fp3>> columns;
};

Fixture BuildFixture()
{
    Fixture out;
    constexpr uint32_t rows = 2;
    out.columns.assign(
        kRCStage3CoupledBankDequantColumns,
        std::vector<gf::Fp3>(
            rows, gf::Fp3::Zero()));
    const uint64_t mantissas[rows] = {3, 5};
    const uint64_t scales[rows] = {1, 3};
    for (uint32_t row = 0;
         row < rows; ++row) {
        const uint64_t b0 =
            scales[row] & 1U;
        const uint64_t b1 =
            (scales[row] >> 1) & 1U;
        const uint64_t factor =
            uint64_t{1} << scales[row];
        out.columns[
            kRCStage3CoupledBankMantissa][row] =
            gf::FromU64_3(mantissas[row]);
        out.columns[
            kRCStage3CoupledBankRepeatedScale][row] =
            gf::FromU64_3(scales[row]);
        out.columns[
            kRCStage3CoupledBankScaleBit0][row] =
            gf::FromU64_3(b0);
        out.columns[
            kRCStage3CoupledBankScaleBit1][row] =
            gf::FromU64_3(b1);
        out.columns[
            kRCStage3CoupledBankScaleFactor][row] =
            gf::FromU64_3(factor);
        out.columns[
            kRCStage3CoupledBankOutput][row] =
            gf::FromU64_3(
                mantissas[row] * factor);
    }
    out.pin.statement_commitment = Seed(0x81);
    out.pin.shape_commitment = Seed(0x82);
    out.pin.sigma = Seed(0x83);
    out.pin.logical_rows = rows;
    out.pin.n_rows = rows;
    out.pin.n_coeffs = rows;
    auto root_columns = out.columns;
    root_columns.emplace_back(
        rows, gf::Fp3::Zero());
    aq::AirConstraintSystem<gf::Fp3> row_shape;
    row_shape.n_rows = rows;
    row_shape.n_columns = root_columns.size();
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            row_shape, root_columns,
            {0, 1, 2, 3, 4, 5});
    BOOST_REQUIRE(r0.valid);
    out.pin.r0_row_group_root =
        r0.base_row_commitment;
    out.pin.pin_commitment =
        ComputeRCStage3CoupledBankDequantPinCommitment(
            out.pin);
    BOOST_REQUIRE(
        !out.pin.pin_commitment.IsNull());
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_splitrap_ctl_coordinator_tests)

BOOST_AUTO_TEST_CASE(
    exact_two_phase_children_and_arity4_parent_roundtrip)
{
    const Fixture fixture = BuildFixture();
    const uint256 public_seed = Seed(0x91);
    CoupledBankEqualityReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ProveCoupledBankEqualityReceiptV1(
            fixture.pin, fixture.columns,
            public_seed, receipt, &why),
        why);
    const auto audit =
        VerifyCoupledBankEqualityReceiptV1(
            fixture.pin, receipt,
            public_seed);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.ordered_phase0_roots);
    BOOST_CHECK(
        audit.challenges_after_all_phase0_roots);
    BOOST_CHECK(
        audit.producer_relation_output_same_trace);
    BOOST_CHECK(
        audit.receiver_projection_same_trace);
    BOOST_CHECK(
        audit.producer_split_rap_verified);
    BOOST_CHECK(
        audit.receiver_split_rap_verified);
    BOOST_CHECK(
        audit.dependent_columns_are_exact_ctl_suffix);
    BOOST_CHECK(audit.proof_owned_terminals);
    BOOST_CHECK(
        audit.dual_lane_public_composition_zero);
    BOOST_CHECK(
        audit.arity4_parent_air_verified);
    BOOST_CHECK(
        audit.child_commitments_bound_in_parent_seed);
    BOOST_CHECK(
        !audit.producer_registered_column_roots_bound);
    BOOST_CHECK(
        !audit.registered_receiver_semantics_bound);
    BOOST_CHECK(
        !audit.child_verifiers_execute_in_parent_air);
    BOOST_CHECK(!audit.recursive_fixed_point);
    BOOST_CHECK(!audit.production_authority);

    const auto cell_map =
        BuildCoupledBankEqualityReceiptCellMapV1(
            fixture.pin, receipt, public_seed);
    BOOST_REQUIRE_MESSAGE(
        cell_map.valid, cell_map.note);
    BOOST_CHECK(
        cell_map.child_codecs_canonical);
    BOOST_CHECK(
        cell_map.parent_batch_codec_canonical);
    BOOST_CHECK(cell_map.all_values_canonical);
    BOOST_CHECK_EQUAL(cell_map.spans.size(), 14U);
    BOOST_CHECK(
        ValidateCoupledBankEqualityReceiptCellMapV1(
            fixture.pin, receipt, public_seed,
            cell_map, &why));

    const auto recursive =
        AssessCoupledBankEqualityRecursiveConsumptionV1(
            fixture.pin, receipt, public_seed);
    BOOST_REQUIRE_MESSAGE(
        recursive.valid, recursive.note);
    BOOST_CHECK(recursive.native_receipt_verified);
    BOOST_CHECK(
        recursive.canonical_cell_map_verified);
    BOOST_CHECK(
        recursive.both_child_programs_canonical);
    BOOST_CHECK(
        recursive.both_local_verifier_relations_execute);
    BOOST_CHECK(
        recursive.parent_proof_verified_natively);
    BOOST_CHECK_GT(recursive.receipt_cells, 0U);
    BOOST_CHECK_GT(
        recursive.local_child_verifier_rows, 0U);
    BOOST_CHECK_GT(
        recursive.sha256_compressions, 0U);
    BOOST_CHECK_EQUAL(
        recursive.receipt_cells_mapped_in_parent,
        0U);
    BOOST_CHECK_EQUAL(
        recursive.recursively_consumed_endpoints,
        0U);
    BOOST_CHECK_EQUAL(
        recursive.recursively_consumed_roles,
        0U);
    BOOST_CHECK(!recursive.recursive_fixed_point);
    BOOST_CHECK(!recursive.authority);
    BOOST_CHECK_EQUAL(recursive.gaps.size(), 8U);
    BOOST_CHECK(
        ValidateCoupledBankEqualityRecursiveConsumptionV1(
            fixture.pin, receipt, public_seed,
            recursive, &why));

    auto bad_map = cell_map;
    bad_map.cells[0] ^= 1U;
    BOOST_CHECK(
        !ValidateCoupledBankEqualityReceiptCellMapV1(
            fixture.pin, receipt, public_seed,
            bad_map, &why));

    auto promoted = recursive;
    promoted.recursively_consumed_endpoints = 1;
    BOOST_CHECK(
        !ValidateCoupledBankEqualityRecursiveConsumptionV1(
            fixture.pin, receipt, public_seed,
            promoted, &why));
}

BOOST_AUTO_TEST_CASE(
    mutations_of_each_phase_and_parent_fail_closed)
{
    const Fixture fixture = BuildFixture();
    const uint256 public_seed = Seed(0x92);
    CoupledBankEqualityReceiptV1 receipt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ProveCoupledBankEqualityReceiptV1(
            fixture.pin, fixture.columns,
            public_seed, receipt, &why),
        why);

    auto bad_r0 = receipt;
    bad_r0.children[0].pin.trace_commitment
        .data()[0] ^= 1U;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_r0,
             public_seed)
             .valid);

    auto bad_rdep = receipt;
    bad_rdep.children[0].proof.batch.groups[1]
        .row_commit.root[0] ^= 1U;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_rdep,
             public_seed)
             .valid);

    auto bad_terminal = receipt;
    bad_terminal.children[0].pin.terminal
        .alpha1_sum =
        gf::Add(
            bad_terminal.children[0].pin.terminal
                .alpha1_sum,
            gf::Fp3::One());
    bad_terminal.terminal_slots[0].terminal =
        bad_terminal.children[0].pin.terminal;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_terminal,
             public_seed)
             .valid);

    auto bad_parent_seed = receipt;
    bad_parent_seed.parent_seed.data()[0] ^= 1U;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_parent_seed,
             public_seed)
             .valid);

    auto bad_padding = receipt;
    bad_padding.terminal_slots[3]
        .child_proof_commitment.data()[0] ^= 1U;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_padding,
             public_seed)
             .valid);

    auto bad_parent_proof = receipt;
    bad_parent_proof.parent_proof.trace_commit
        .data()[0] ^= 1U;
    BOOST_CHECK(
        !VerifyCoupledBankEqualityReceiptV1(
             fixture.pin, bad_parent_proof,
             public_seed)
             .valid);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::splitrap_ctl
