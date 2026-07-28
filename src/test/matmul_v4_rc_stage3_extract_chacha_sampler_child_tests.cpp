// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_extract_chacha_sampler_child.h>

#include <cstdlib>

namespace child =
    matmul::v4::rc::extract_chacha_sampler_child;
namespace gf = matmul::v4::rc::gkr_field;

namespace {

uint256 H(uint8_t tag)
{
    uint256 out;
    out.SetNull();
    out.data()[0] = tag;
    out.data()[31] = static_cast<uint8_t>(tag ^ 0xa5U);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_extract_chacha_sampler_child_tests)

BOOST_AUTO_TEST_CASE(retained_node_is_fail_closed)
{
    child::TileStatementV1 statement;
    BOOST_CHECK(
        child::ComputeRetainedNodeCommitmentV1(statement)
            .IsNull());
    statement.statement_commitment = H(1);
    statement.public_fs_seed = H(2);
    statement.prf_key = H(3);
    statement.chacha_blocks = 1;
    statement.candidate_rows = 1;
    statement.trace_rows = 2048;
    statement.public_boundary_statement = H(4);
    statement.r0_root = H(5);
    statement.position_cells.resize(1);
    statement.input_bit_cells.resize(1);
    BOOST_CHECK(
        !child::ComputeRetainedNodeCommitmentV1(statement)
             .IsNull());
    statement.candidate_rows = 0;
    BOOST_CHECK(
        child::ComputeRetainedNodeCommitmentV1(statement)
            .IsNull());
}

BOOST_AUTO_TEST_CASE(
    challenge_domains_and_preprocessed_columns_are_distinct)
{
    child::TileStatementV1 statement;
    statement.statement_commitment = H(0x21);
    statement.public_fs_seed = H(0x22);
    statement.prf_key = H(0x23);
    statement.row = 7;
    statement.block = 9;
    statement.chacha_blocks = 1;
    statement.candidate_rows = 64;
    statement.trace_rows = 2048;
    statement.scale_e = 3;
    statement.r0_root = H(0x24);
    const auto challenge =
        child::DeriveChallengePairForAuditV1(statement);
    // Regression: serializing decayed C-string labels made the two labels
    // identical and allowed alpha == gamma.
    BOOST_CHECK(!gf::Eq(challenge[0], challenge[1]));

    child::aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 2;
    const std::vector<gf::Fp3> canonical{
        gf::Fp3::One(), gf::Fp3::Zero()};
    cs.preprocessed.emplace_back(1, canonical);
    std::vector<std::vector<gf::Fp3>> columns(
        2, std::vector<gf::Fp3>(
               2, gf::Fp3::Zero()));
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        child::MaterializeVerifierOwnedPreprocessedV1(
            cs, columns, &why),
        why);
    BOOST_CHECK_EQUAL(
        columns[1].size(), canonical.size());
    for (uint32_t row = 0; row < canonical.size(); ++row) {
        BOOST_CHECK(gf::Eq(columns[1][row], canonical[row]));
    }

    cs.preprocessed.emplace_back(
        1,
        std::vector<gf::Fp3>{
            gf::Fp3::Zero(), gf::Fp3::One()});
    BOOST_CHECK(
        !child::MaterializeVerifierOwnedPreprocessedV1(
            cs, columns, &why));
}

BOOST_AUTO_TEST_CASE(
    safe_split_rap_binds_chacha_nibbles_sampler_mix_and_output)
{
    if (std::getenv(
            "BTX_RUN_EXTRACT_CHACHA_SAMPLER_CHILD") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_EXTRACT_CHACHA_SAMPLER_CHILD=1 "
            "for the complete local Extract tile proof");
        return;
    }
    std::array<int64_t, 32> input{};
    for (uint32_t i = 0; i < input.size(); ++i) {
        input[i] =
            i & 1U
            ? -static_cast<int64_t>(
                  UINT64_C(0x100000000) + 17U * i)
            : static_cast<int64_t>(
                  UINT64_C(0x100000000) + 29U * i);
    }
    child::TileProofV1 proof;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        child::ProveTileV1(
            H(0x11), H(0x12), H(0x13),
            7, 9, input, proof, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        child::VerifyTileV1(proof, &why), why);
    BOOST_CHECK(proof.native_verified);
    BOOST_CHECK(!proof.normalized_parent_consumed);
    BOOST_CHECK_EQUAL(
        proof.statement.output_cells.size(), 32U);
    BOOST_CHECK_EQUAL(
        proof.statement.position_cells.size(),
        proof.statement.candidate_rows);
    BOOST_CHECK_EQUAL(
        proof.statement.input_bit_cells.size(),
        proof.statement.candidate_rows);

    auto schedule_attack = proof;
    ++schedule_attack.statement.output_cells[0].column;
    schedule_attack.statement.retained_node_commitment =
        child::ComputeRetainedNodeCommitmentV1(
            schedule_attack.statement);
    BOOST_CHECK(
        !child::VerifyTileV1(
            schedule_attack, &why));

    auto nonce_attack = proof;
    ++nonce_attack.statement.row;
    nonce_attack.statement.retained_node_commitment =
        child::ComputeRetainedNodeCommitmentV1(
            nonce_attack.statement);
    BOOST_CHECK(
        !child::VerifyTileV1(nonce_attack, &why));

    auto proof_attack = proof;
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries[0]
             .group_rows.empty());
    BOOST_REQUIRE(
        !proof_attack.quotient.batch.queries[0]
             .group_rows[0].values.empty());
    auto& value =
        proof_attack.quotient.batch.queries[0]
            .group_rows[0].values[0];
    value = gf::Add(value, gf::Fp3::One());
    BOOST_CHECK(
        !child::VerifyTileV1(
            proof_attack, &why));
}

BOOST_AUTO_TEST_SUITE_END()
