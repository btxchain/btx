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

#include <test/util/setup_common.h>

#include <algorithm>
#include <array>
#include <utility>
#include <vector>

namespace {

namespace eq =
    matmul::v4::rc::normalized_parent_external_producer_equality;
namespace streaming =
    matmul::v4::rc::streaming_episode_closure;
namespace aggregate =
    matmul::v4::rc::episode_external_producer_aggregate;
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

void EmptyParent(AirCS& cs, std::vector<std::vector<gf::Fp3>>& columns)
{
    cs = {};
    cs.n_rows = 2;
    cs.n_columns = 0;
    columns.clear();
}

/**
 * Deterministic streaming receipt whose structural role-export premises hold
 * (commitment + A/B/Y terminal flags) without mining or FRI replay.
 */
streaming::StreamingEpisodeClosureReceiptV1
SyntheticStreamingReceiptFixtureV1()
{
    streaming::StreamingEpisodeClosureReceiptV1 receipt;
    receipt.schedule.statement_commitment = H(0x81);
    receipt.schedule.schedule_commitment = H(0x82);

    streaming::StreamedLayerClosureV1 layer;
    layer.layer_ordinal = 0;
    layer.shape.layer_ordinal = 0;
    layer.shape.shape_commitment = H(0x83);
    layer.consumer_leaf_begin = 0;
    layer.consumer_bundle.bundle_commitment = H(0x84);
    layer.closure.version = aggregate::kVersionV1;
    layer.closure.layer_ordinal = 0;
    layer.closure.operand_a_vector_root_alg = H(0xa1);
    layer.closure.operand_b_vector_root_alg = H(0xb2);
    layer.closure.output_y_vector_root_alg = H(0xc3);
    layer.closure.closure_commitment = H(0x85);
    layer.closure.proof_owned_terminal_cancellation = true;
    layer.closure.all_children_proof_verified = true;
    layer.closure.role_export_equality_constrained = false;
    layer.closure.production_authority = false;
    layer.extract_prf = H(0x86);
    layer.gemm_y_vector_root_alg =
        layer.closure.output_y_vector_root_alg;
    layer.extract_role_proof_consumed = false;
    layer.production_authority = false;
    layer.retained_commitment =
        streaming::ComputeStreamedLayerClosureCommitmentV1(
            layer);
    BOOST_REQUIRE(!layer.retained_commitment.IsNull());

    receipt.layers.push_back(std::move(layer));
    receipt.round_roots = {H(0x91)};
    receipt.episode_digest = H(0x92);
    receipt.every_gemm_child_verified = true;
    receipt.extract_role_children_consumed = false;
    receipt.normalized_parent_consumed = false;
    receipt.production_authority = false;
    receipt.receipt_commitment =
        streaming::
            ComputeStreamingEpisodeClosureReceiptCommitmentV1(
                receipt);
    BOOST_REQUIRE(!receipt.receipt_commitment.IsNull());
    return receipt;
}

std::vector<eq::ParentExportPinV1> PinsFromReceipt(
    const streaming::StreamingEpisodeClosureReceiptV1& receipt)
{
    std::vector<eq::ParentExportPinV1> pins;
    for (const auto& layer : receipt.layers) {
        const std::array<
            std::pair<eq::TerminalKindV1, uint256>, 3>
            terminals = {{
                {eq::TerminalKindV1::OperandA,
                 layer.closure.operand_a_vector_root_alg},
                {eq::TerminalKindV1::OperandB,
                 layer.closure.operand_b_vector_root_alg},
                {eq::TerminalKindV1::OutputY,
                 layer.closure.output_y_vector_root_alg},
            }};
        for (const auto& [kind, root] : terminals) {
            eq::ParentExportPinV1 pin;
            pin.kind = kind;
            pin.layer_ordinal = layer.layer_ordinal;
            pin.export_vector_root_alg = root;
            pins.push_back(pin);
        }
    }
    return pins;
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
    auto receipt = SyntheticStreamingReceiptFixtureV1();
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
    auto receipt = SyntheticStreamingReceiptFixtureV1();
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
    // Receipt commitments authenticate bytes, not truth. A synthetic receipt
    // with self-asserted child-verification flags must not become production
    // evidence, with or without a parent certificate.
    const auto receipt = SyntheticStreamingReceiptFixtureV1();
    std::string why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, nullptr, &why);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK(!assessment.all_streaming_children_verified);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_CHECK(!assessment.parent_certificate_verified);
    BOOST_CHECK(
        !assessment.all_role_export_equality_constrained);
}

BOOST_AUTO_TEST_CASE(
    synthetic_streaming_receipt_cannot_close_production_equality)
{
    // A structurally valid same-parent alias certificate is useful as a local
    // wiring fixture, but it cannot authenticate the receipt's child proofs.
    const auto receipt = SyntheticStreamingReceiptFixtureV1();
    const auto pins = PinsFromReceipt(receipt);
    BOOST_REQUIRE_EQUAL(pins.size(), 3U);

    AirCS cs;
    std::vector<std::vector<gf::Fp3>> columns;
    EmptyParent(cs, columns);
    eq::ParentRoleExportEqualityCertificateV1 certificate;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        eq::AttachParentRoleExportEqualityTerminalsV1(
            cs, columns, receipt.receipt_commitment, pins,
            pins, certificate, &why),
        why);
    BOOST_CHECK(
        !eq::VerifyParentRoleExportEqualityCertificateV1(
            receipt, certificate, &why));

    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, &certificate, &why);
    BOOST_CHECK(!assessment.streaming_receipt_verified);
    BOOST_CHECK(!assessment.parent_certificate_verified);
    BOOST_CHECK(!assessment.all_streaming_children_verified);
    BOOST_CHECK(
        !assessment.all_role_export_equality_constrained);
    BOOST_CHECK(
        !assessment
            .external_producer_terminal_equality_complete);
    BOOST_CHECK(
        why.find("streaming_receipt_invalid") !=
        std::string::npos);
    BOOST_CHECK_EQUAL(
        rc::air_recurse::CountWitnessViolationsOnH(
            cs, columns),
        0U);

    // Streaming local verifier must still reject a forged parent-attachment
    // claim on the layer closure itself (fail-closed local ingress).
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
