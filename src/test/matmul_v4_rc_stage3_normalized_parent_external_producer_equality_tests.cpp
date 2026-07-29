// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>

#include <test/util/setup_common.h>

#include <algorithm>

namespace {

namespace eq =
    matmul::v4::rc::normalized_parent_external_producer_equality;
namespace streaming =
    matmul::v4::rc::streaming_episode_closure;

uint256 H(unsigned char tag)
{
    uint256 out;
    std::fill(out.begin(), out.end(), tag);
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_normalized_parent_external_producer_equality_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(terminal_kind_names_are_stable)
{
    BOOST_CHECK_EQUAL(
        eq::TerminalKindNameV1(eq::TerminalKindV1::OperandA),
        "operand_a");
    BOOST_CHECK_EQUAL(
        eq::TerminalKindNameV1(eq::TerminalKindV1::OperandB),
        "operand_b");
    BOOST_CHECK_EQUAL(
        eq::TerminalKindNameV1(eq::TerminalKindV1::OutputY),
        "output_y");
}

BOOST_AUTO_TEST_CASE(
    missing_streaming_receipt_keeps_equality_open)
{
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            nullptr, &why);
    BOOST_CHECK(assessment.streaming_receipt_present ==
                false);
    BOOST_CHECK(assessment.streaming_receipt_verified ==
                false);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(!assessment.all_streaming_children_verified);
    BOOST_CHECK(
        !assessment.all_role_export_equality_constrained);
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK_EQUAL(
        assessment.residuals.front(),
        "streaming_episode_closure_receipt_missing");
    BOOST_CHECK(
        why.find("streaming_receipt_missing") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    empty_default_receipt_is_invalid_and_keeps_equality_open)
{
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &why);

    BOOST_CHECK(assessment.streaming_receipt_present);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK_EQUAL(assessment.layer_count, 0U);
    BOOST_CHECK_EQUAL(assessment.terminals_required, 0U);
    BOOST_CHECK(assessment.terminals.empty());
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_invalid:") !=
        std::string::npos);
    BOOST_CHECK(
        why.find("streaming_receipt_invalid") !=
        std::string::npos);
    BOOST_CHECK(
        assessment.note.find(
            "external_producer_terminal_equality_pending") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    empty_shaped_receipt_with_statement_flags_still_invalid)
{
    // Constructible without mining: statement flags look like a handoff,
    // but the empty schedule/layers cannot verify.
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    receipt.every_gemm_child_verified = true;
    receipt.extract_role_children_consumed = false;
    receipt.normalized_parent_consumed = false;
    receipt.production_authority = false;
    receipt.receipt_commitment =
        streaming::
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                receipt);

    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &why);

    BOOST_CHECK(assessment.streaming_receipt_present);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(assessment.terminals.empty());
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_invalid:") !=
        std::string::npos);
    BOOST_CHECK(
        why.find("streaming_receipt_invalid") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    production_authority_receipt_shape_rejected_fail_closed)
{
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    receipt.every_gemm_child_verified = true;
    receipt.production_authority = true;
    receipt.receipt_commitment =
        streaming::
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                receipt);

    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &why);

    BOOST_CHECK(assessment.streaming_receipt_present);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(
        !assessment.all_role_export_equality_constrained);
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_invalid:") !=
        std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    commitment_mismatch_receipt_keeps_equality_open)
{
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    receipt.every_gemm_child_verified = true;
    receipt.receipt_commitment = H(0xaa);

    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &why);

    BOOST_CHECK(assessment.streaming_receipt_present);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_invalid:") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
