// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_coupled_gemm_range_ctl_v3.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>

namespace {

namespace rc = matmul::v4::rc;
namespace v3 = rc::coupled_gemm_range_ctl_v3;
namespace gf = rc::gkr_field;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{
        Span<const unsigned char>{
            bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Coupled;
    out.public_inputs.height = 700;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.coupled_profile = 2;
    out.public_inputs.transcript_version = 4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0xff);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.coupled_digest = H(0x44);
    out.public_inputs.final_digest = H(0x44);
    return out;
}

rc::RCStage3CoupledShape Shape()
{
    rc::RCStage3CoupledShape out;
    out.barriers = 4;
    out.lobes = 1;
    out.lobe_width = 32;
    out.bank_pages = 1;
    out.rows_per_lobe = 1;
    out.pages_per_barrier_lobe = 1;
    out.transcript_version = 4;
    out.full_bank_schedule = true;
    return out;
}

std::vector<rc::RCStage3CoupledGemmOpening> Openings(
    int64_t y = 32)
{
    std::vector<rc::RCStage3CoupledGemmOpening> out(4);
    for (auto& opening : out) {
        opening.operand_a.assign(32, 1);
        opening.operand_b.assign(32 * 32, 1);
        opening.output_y.assign(32, y);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_coupled_gemm_range_ctl_v3_tests)

BOOST_AUTO_TEST_CASE(
    proves_every_terminal_and_rejects_drop_duplicate_reorder_root_challenge_and_value_attacks)
{
    const auto statement = Statement();
    const auto shape = Shape();
    v3::ProductV3 honest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        v3::ProveV3(
            statement, shape, Openings(),
            honest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        v3::VerifyV3(
            statement, shape, honest, &why),
        why);
    BOOST_REQUIRE_EQUAL(honest.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(
        honest.shards[0].gemm_children.size(), 4U);
    BOOST_CHECK_EQUAL(
        honest.expected_output_cells, 128U);
    BOOST_CHECK(honest.every_cell_partitioned);
    BOOST_CHECK(honest.every_child_proof_verified);
    BOOST_CHECK(honest.every_terminal_sum_zero);
    BOOST_CHECK(!honest.normalized_parent_consumed);
    BOOST_CHECK(!honest.production_authority);

    v3::ParentReceiptBundleV3 receipts;
    BOOST_REQUIRE_MESSAGE(
        v3::BuildVerifiedParentReceiptsV3(
            statement, shape, honest,
            receipts, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        v3::ValidateParentReceiptsV3(
            statement, shape, honest,
            receipts, &why),
        why);
    BOOST_REQUIRE_EQUAL(receipts.shards.size(), 1U);
    BOOST_REQUIRE_EQUAL(
        receipts.shards[0].role[0].nodes.size(), 4U);
    BOOST_REQUIRE_EQUAL(
        receipts.shards[0].role[1].nodes.size(), 1U);
    BOOST_CHECK(
        receipts.every_split_rap_child_verified);
    BOOST_CHECK(
        receipts.every_dual_fp3_terminal_exported);
    BOOST_CHECK(
        receipts.every_shard_terminal_cancelled);
    BOOST_CHECK(
        receipts.shards[0]
            .dual_fp3_terminal_cancellation);
    BOOST_CHECK(
        receipts.shards[0].role[0].terminal ==
        honest.shards[0].gemm_role.terminal);
    BOOST_CHECK(
        receipts.shards[0].role[1].terminal ==
        honest.shards[0].range_role.terminal);
    BOOST_CHECK(!receipts.normalized_parent_consumed);

    auto receipt_terminal_attack = receipts;
    receipt_terminal_attack.shards[0].role[1]
        .terminal.alpha1_sum =
        gf::Add(
            receipt_terminal_attack.shards[0]
                .role[1].terminal.alpha1_sum,
            gf::Fp3::One());
    BOOST_CHECK(!v3::ValidateParentReceiptsV3(
        statement, shape, honest,
        receipt_terminal_attack, nullptr));

    auto receipt_proof_attack = receipts;
    auto& retained_query =
        receipt_proof_attack.shards[0].role[0]
            .nodes[0].proof.batch.queries[0];
    BOOST_REQUIRE(!retained_query.group_rows.empty());
    BOOST_REQUIRE(
        !retained_query.group_rows[0].values.empty());
    retained_query.group_rows[0].values[0] =
        gf::Add(
            retained_query.group_rows[0].values[0],
            gf::Fp3::One());
    BOOST_CHECK(!v3::ValidateParentReceiptsV3(
        statement, shape, honest,
        receipt_proof_attack, nullptr));

    auto dropped = honest;
    dropped.shards[0].gemm_children.pop_back();
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, dropped, nullptr));

    auto duplicated = honest;
    duplicated.shards[0].gemm_children[1] =
        duplicated.shards[0].gemm_children[0];
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, duplicated, nullptr));

    auto reordered = honest;
    std::swap(
        reordered.shards[0].gemm_children[0],
        reordered.shards[0].gemm_children[1]);
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, reordered, nullptr));

    auto root_attack = honest;
    root_attack.shards[0].gemm_children[0]
        .base_row_commitment = H(0xa5);
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, root_attack, nullptr));

    auto relation_root_attack = honest;
    relation_root_attack.shards[0].gemm_children[0]
        .dot_pin.column_roots[
            rc::kRCStage3CoupledGemmY].root = H(0xb6);
    relation_root_attack.shards[0].gemm_children[0]
        .dot_pin.pin_commitment =
        rc::ComputeRCStage3CoupledGemmDotPinCommitment(
            relation_root_attack.shards[0]
                .gemm_children[0].dot_pin);
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape,
        relation_root_attack, nullptr));

    auto challenge_attack = honest;
    challenge_attack.shards[0].challenges.alpha1 =
        gf::Add(
            challenge_attack.shards[0]
                .challenges.alpha1,
            gf::Fp3::One());
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, challenge_attack, nullptr));

    auto terminal_attack = honest;
    terminal_attack.shards[0].range_child
        .terminal.alpha2_sum =
        gf::Add(
            terminal_attack.shards[0].range_child
                .terminal.alpha2_sum,
            gf::Fp3::One());
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, terminal_attack, nullptr));

    auto value_attack = honest;
    auto& query = value_attack.shards[0]
        .gemm_children[0].proof.batch.queries[0];
    BOOST_REQUIRE(!query.group_rows.empty());
    BOOST_REQUIRE(!query.group_rows[0].values.empty());
    query.group_rows[0].values[0] =
        gf::Add(
            query.group_rows[0].values[0],
            gf::Fp3::One());
    BOOST_CHECK(!v3::VerifyV3(
        statement, shape, value_attack, nullptr));
}

BOOST_AUTO_TEST_CASE(
    prover_rejects_wrong_gemm_sum_and_out_of_range_output)
{
    const auto statement = Statement();
    const auto shape = Shape();
    v3::ProductV3 proof;
    std::string why;
    BOOST_CHECK(!v3::ProveV3(
        statement, shape, Openings(31),
        proof, &why));
    BOOST_CHECK(!v3::ProveV3(
        statement, shape, Openings(100'000),
        proof, &why));
}

BOOST_AUTO_TEST_SUITE_END()
