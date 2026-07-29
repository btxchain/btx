// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_stage3_episode_external_producer_aggregate.h>
#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>
#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>
#include <primitives/block.h>

#include <test/util/setup_common.h>

#include <algorithm>
#include <cstdlib>

namespace {

namespace eq =
    matmul::v4::rc::normalized_parent_external_producer_equality;
namespace streaming =
    matmul::v4::rc::streaming_episode_closure;
namespace gf = matmul::v4::rc::gkr_field;
namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;

using AirCS = aq::AirConstraintSystem<gf::Fp3>;

uint256 H(unsigned char tag)
{
    uint256 out;
    std::fill(out.begin(), out.end(), tag);
    return out;
}

rc::RCEpisodeParams TinyParams()
{
    rc::RCEpisodeParams out;
    out.rounds = 1;
    out.d_head = 32;
    out.n_q = 32;
    out.n_ctx = 32;
    out.L_lyr = 1;
    out.d_model = 32;
    out.d_ff = 32;
    out.b_seq = 32;
    out.T_leaf = 64;
    return out;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 151;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.coupled_profile = 3;
    out.public_inputs.transcript_version = rc::ENC_RC_V3;
    out.public_inputs.program_consensus_pin.version = 1;
    out.public_inputs.program_consensus_pin
        .recursive_alg_hash_root = H(0x11);
    out.public_inputs.program_consensus_pin
        .external_sha256d_audit_root = H(0x12);
    out.public_inputs.program_consensus_pin
        .registry_binding = H(0x13);
    out.public_inputs.header_commitment = H(0x21);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.target = H(0x23);
    out.public_inputs.sigma = H(0x24);
    return out;
}

void EmptyParent(AirCS& cs, std::vector<std::vector<gf::Fp3>>& columns)
{
    cs = {};
    cs.n_rows = 2;
    cs.n_columns = 0;
    columns.clear();
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
    BOOST_CHECK(
        eq::TerminalExportEndpointV1(
            eq::TerminalKindV1::OperandA) ==
        rc::RCStage3RelationEndpoint::EpisodeGemmOperandA);
    BOOST_CHECK(
        eq::TerminalExportEndpointV1(
            eq::TerminalKindV1::OperandB) ==
        rc::RCStage3RelationEndpoint::EpisodeGemmOperandB);
    BOOST_CHECK(
        eq::TerminalExportEndpointV1(
            eq::TerminalKindV1::OutputY) ==
        rc::RCStage3RelationEndpoint::EpisodeGemmOutputY);
}

BOOST_AUTO_TEST_CASE(
    missing_streaming_receipt_keeps_equality_open)
{
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            nullptr, nullptr, &why);
    BOOST_CHECK(assessment.streaming_receipt_present ==
                false);
    BOOST_CHECK(assessment.streaming_receipt_verified ==
                false);
    BOOST_CHECK(!assessment.parent_certificate_present);
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
            &receipt, nullptr, &why);

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
            &receipt, nullptr, &why);

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
            &receipt, nullptr, &why);

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
            &receipt, nullptr, &why);

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

BOOST_AUTO_TEST_CASE(
    parent_air_attach_closes_role_export_when_roots_match)
{
    // Always-on fixture: parent AIR hosts and equality-constrains synthetic
    // A/B/Y VectorRootAlg terminals.  Premises hold ⇒ certificate closes.
    const uint256 receipt_commitment = H(0x71);
    const std::array<uint256, 3> roots = {
        H(0xa1), H(0xb2), H(0xc3)};
    std::vector<eq::ParentExportPinV1> expected;
    std::vector<eq::ParentExportPinV1> exports;
    for (uint32_t i = 0; i < roots.size(); ++i) {
        eq::ParentExportPinV1 pin;
        pin.kind = static_cast<eq::TerminalKindV1>(i);
        pin.layer_ordinal = 0;
        pin.export_vector_root_alg = roots[i];
        expected.push_back(pin);
        exports.push_back(pin);
    }

    AirCS cs;
    std::vector<std::vector<gf::Fp3>> columns;
    EmptyParent(cs, columns);
    eq::ParentRoleExportEqualityCertificateV1 certificate;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        eq::AttachParentRoleExportEqualityTerminalsV1(
            cs, columns, receipt_commitment, expected,
            exports, certificate, &why),
        why);
    BOOST_CHECK(certificate.all_terminals_constrained);
    BOOST_CHECK_EQUAL(certificate.terminals_required, 3U);
    BOOST_CHECK_EQUAL(certificate.terminals_constrained, 3U);
    BOOST_CHECK(
        !certificate.certificate_commitment.IsNull());
    BOOST_CHECK_EQUAL(
        certificate.certificate_commitment,
        eq::ComputeParentRoleExportEqualityCertificateCommitmentV1(
            certificate));
    for (const auto& join : certificate.joins) {
        BOOST_CHECK(join.roots_equal);
        BOOST_CHECK(join.root_words_same_parent_aliased);
        BOOST_CHECK(join.expected_pinned);
        BOOST_CHECK(join.export_pinned_or_reused);
    }
    BOOST_CHECK_EQUAL(
        rc::air_recurse::CountWitnessViolationsOnH(
            cs, columns),
        0U);

    // Mismatched export root cannot close.
    exports[1].export_vector_root_alg = H(0xee);
    EmptyParent(cs, columns);
    eq::ParentRoleExportEqualityCertificateV1 rejected;
    BOOST_CHECK(
        !eq::AttachParentRoleExportEqualityTerminalsV1(
            cs, columns, receipt_commitment, expected,
            exports, rejected, &why));
    BOOST_CHECK(!rejected.all_terminals_constrained);
}

BOOST_AUTO_TEST_CASE(
    assessor_stays_open_without_parent_certificate_even_if_receipt_flags_look_ready)
{
    // Streaming local closures intentionally keep
    // role_export_equality_constrained=false.  Without a parent certificate the
    // assessor must not claim equality complete.
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    receipt.every_gemm_child_verified = true;
    receipt.receipt_commitment =
        streaming::
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                receipt);
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, nullptr, &why);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(!assessment.parent_certificate_verified);
}

BOOST_AUTO_TEST_CASE(
    real_streaming_receipt_parent_attach_makes_equality_complete)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_PARENT_ROLE_EXPORT_EQUALITY") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_PARENT_ROLE_EXPORT_EQUALITY=1 "
            "for mine→streaming-receipt→parent-attach→assess "
            "complete");
        return;
    }

    const auto statement = Statement();
    const auto params = TinyParams();
    CBlockHeader header;
    header.nVersion = 1;
    header.hashPrevBlock = H(0x51);
    header.hashMerkleRoot = H(0x52);
    header.nTime = 1700000000U;
    header.nBits = 0x207fffffU;
    header.nNonce = 7;

    streaming::StreamingEpisodeClosureSink sink(
        statement, params);
    const uint256 digest =
        rc::MineRCEpisodeWithProofWitness(
            header, params, 151, sink);
    BOOST_REQUIRE(!digest.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(sink.Complete(&why), why);
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    BOOST_REQUIRE_MESSAGE(
        sink.BuildReceipt(receipt, &why), why);

    std::vector<eq::ParentExportPinV1> pins;
    BOOST_REQUIRE_MESSAGE(
        eq::BuildHostedExportPinsFromStreamingReceiptV1(
            receipt, pins, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        pins.size(), receipt.layers.size() * 3U);

    AirCS cs;
    std::vector<std::vector<gf::Fp3>> columns;
    EmptyParent(cs, columns);
    eq::ParentRoleExportEqualityCertificateV1 certificate;
    BOOST_REQUIRE_MESSAGE(
        eq::AttachParentRoleExportEqualityV1(
            cs, columns, receipt, pins, certificate,
            &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        eq::VerifyParentRoleExportEqualityCertificateV1(
            receipt, certificate, &why),
        why);

    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &certificate, &why);
    BOOST_CHECK(assessment.streaming_receipt_verified);
    BOOST_CHECK(assessment.parent_certificate_verified);
    BOOST_CHECK(assessment.all_streaming_children_verified);
    BOOST_CHECK(
        assessment.all_role_export_equality_constrained);
    BOOST_CHECK(
        assessment
            .external_producer_terminal_equality_complete);
    BOOST_CHECK_EQUAL(
        assessment.terminals_role_export_joined,
        assessment.terminals_required);
    BOOST_CHECK(
        why.find("all_terminals_joined") !=
        std::string::npos);
    BOOST_CHECK_EQUAL(
        rc::air_recurse::CountWitnessViolationsOnH(
            cs, columns),
        0U);

    // Streaming local verifier must still reject a forged parent-attachment
    // claim on the layer closure itself.
    BOOST_REQUIRE(!receipt.layers.empty());
    auto forged = receipt.layers.front().closure;
    forged.role_export_equality_constrained = true;
    BOOST_CHECK(
        !rc::episode_external_producer_aggregate::
            VerifyLayerClosureV1(
                receipt.layers.front().shape,
                receipt.layers.front().consumer_bundle,
                receipt.layers.front().consumer_leaf_begin,
                forged.operand_a_vector_root_alg,
                forged.operand_b_vector_root_alg,
                forged.output_y_vector_root_alg,
                forged, &why));
}

BOOST_AUTO_TEST_SUITE_END()
