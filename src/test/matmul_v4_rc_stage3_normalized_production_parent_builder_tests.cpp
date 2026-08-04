// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <consensus/params.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_stage3_episode_external_producer_aggregate.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_normalized_parent_external_producer_equality.h>
#include <matmul/matmul_v4_rc_stage3_normalized_production_parent_builder.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_streaming_episode_closure.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>

#include <algorithm>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace rc = matmul::v4::rc;
namespace builder =
    rc::normalized_production_parent_builder;
namespace eq =
    rc::normalized_parent_external_producer_equality;
namespace fp = rc::recursive_fixedpoint;
namespace streaming = rc::streaming_episode_closure;
namespace aggregate = rc::episode_external_producer_aggregate;

uint256 H(unsigned char tag)
{
    uint256 out;
    std::fill(out.begin(), out.end(), tag);
    return out;
}

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

Consensus::Params FixtureParams()
{
    Consensus::Params params;
    params.fMatMulPOW = true;
    params.nMatMulV4Height = 1;
    params.nMatMulRCHeight = 1;
    params.nMatMulRCProfile = 2;
    params.fMatMulRCUseToyDims = true;
    params.nMatMulV4Dimension = 256;
    params.nMatMulRCCoupledHeight = 1;
    params.nMatMulRCCoupledProfile = 2;
    params.fMatMulRCCoupledUseToyDims = true;
    params.hashMatMulRCStage3ProgramRegistryAlgRoot = H(0x91);
    params.hashMatMulRCStage3ProgramRegistryShaAuditRoot =
        H(0x92);
    params.hashMatMulRCStage3ProgramRegistryBinding = H(0x93);
    params.powLimit = uint256{
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"};
    return params;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_normalized_production_parent_builder_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    status_names_include_built_and_fail_closed_variants)
{
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::Built),
        "built");
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::
                CompleteRelationParentUnavailable),
        "complete_relation_parent_unavailable");
    BOOST_CHECK_EQUAL(
        builder::ProductionParentBuildStatusNameV1(
            builder::ProductionParentBuildStatusV1::
                InvalidRequest),
        "invalid_request");
}

BOOST_AUTO_TEST_CASE(
    role_audit_stays_open_while_recursive_children_is_false)
{
    // Tip soundness: RecursiveChildren/CompleteFP remain false until ordinary
    // V3 tape/consumer leaves recurse under a narrow parent.  Built cannot
    // honestly clear RoleAudit while those gates are false.
    BOOST_CHECK(
        !rc::kRCStage3RelationClosureRecursiveChildrenExecutable);
    BOOST_CHECK(!fp::kCompleteRecursiveFixedPointExecutable);
    BOOST_CHECK(!rc::kRCStage3RelationClosureAuthorityReady);
    BOOST_CHECK(!fp::kRecursiveFixedPointConsensusAuthority);

    const auto audit =
        rc::CurrentRCStage3RelationClosureRoleAudit();
    BOOST_REQUIRE_EQUAL(audit.size(), 14U);
    uint16_t complete = 0;
    for (const auto& role : audit) {
        complete += role.role_complete ? 1 : 0;
        BOOST_CHECK(!role.recursive_ctl_consumption);
    }
    BOOST_CHECK_LT(complete, 14U);

    const auto cells =
        rc::CurrentRCStage3RelationEndpointCellAudit();
    BOOST_REQUIRE_EQUAL(cells.size(), 52U);
    uint16_t consumed = 0;
    for (const auto& cell : cells) {
        consumed += cell.recursive_child_consumed ? 1 : 0;
    }
    BOOST_CHECK_EQUAL(consumed, 0U);
}

BOOST_AUTO_TEST_CASE(
    build_for_solved_block_rejects_invalid_request_fail_closed)
{
    builder::ProductionParentBuildInputV1 input;
    builder::consumer::CanonicalRelationParentProductV1 product;
    std::string why;
    const auto status =
        builder::BuildForSolvedBlockV1(
            input, product, &why);
    BOOST_CHECK(
        status ==
        builder::ProductionParentBuildStatusV1::
            InvalidRequest);
    BOOST_CHECK(
        why.find("request") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(
    build_for_solved_block_reaches_candidate_inputs_before_failing)
{
    // The legacy mutable-global RoleAudit precheck is gone. A composed request
    // now reaches immutable candidate construction and fails on its actual
    // missing winner capture, not process-global recursive evidence.
    auto params = FixtureParams();
    CBlock block;
    block.nVersion = 4;
    block.nTime = 1;
    block.nBits = 0x2100ffffU;
    block.nNonce = 7;
    block.nNonce64 = 7;
    block.matmul_dim = 256;
    block.seed_a = H(0x11);
    block.seed_b = H(0x22);
    block.matmul_digest = H(0x33);

    builder::ProductionParentBuildInputV1 input;
    input.solved_block = &block;
    input.params = &params;
    input.height = 1;
    input.target = uint256{
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"};

    builder::consumer::CanonicalRelationParentProductV1 product;
    std::string why;
    const auto status =
        builder::BuildForSolvedBlockV1(
            input, product, &why);
    BOOST_CHECK(
        status ==
        builder::ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable);
    BOOST_CHECK(
        why.find("relation_parent:") !=
        std::string::npos);
    BOOST_CHECK(
        why.find("winner_episode_capture_binding") !=
        std::string::npos);
    BOOST_CHECK(
        why.find(
            "recursive_semantic_child_consumption_open") ==
        std::string::npos);
    BOOST_CHECK(why.find("built") == std::string::npos);

    std::string eq_why;
    const auto assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            nullptr, nullptr, &eq_why);
    BOOST_CHECK(
        !assessment
             .external_producer_terminal_equality_complete);
    BOOST_REQUIRE(!assessment.residuals.empty());
    BOOST_CHECK(
        assessment.residuals.front().find(
            "streaming_episode_closure_receipt_missing") !=
        std::string::npos);

    const auto receipt = SyntheticStreamingReceiptFixtureV1();
    const auto synth_assessment =
        eq::AssessStreamingRoleExportEqualityV1(
            &receipt, nullptr, &eq_why);
    BOOST_CHECK(!synth_assessment.streaming_receipt_verified);
    BOOST_CHECK(
        !synth_assessment
             .external_producer_terminal_equality_complete);
}

BOOST_AUTO_TEST_CASE(
    convert_built_fail_closes_without_production_authority)
{
    // ConvertProductionAuthorityCandidateToBuiltV1 is the NAV3 finalization
    // step BuildForSolvedBlockV1 uses after RoleAudit + equality close.  Without
    // production_authority it must stay fail-closed (no Built shortcut).
    auto params = FixtureParams();
    CBlock block;
    block.nVersion = 4;
    builder::ProductionParentBuildInputV1 input;
    input.solved_block = &block;
    input.params = &params;
    input.height = 1;
    input.target = uint256{
        "ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff"};

    builder::ProductionRelationParentCandidateV1 candidate;
    candidate.local_parent_valid = true;
    candidate.production_authority = false;
    builder::consumer::CanonicalRelationParentProductV1 product;
    std::string why;
    const auto status =
        builder::ConvertProductionAuthorityCandidateToBuiltV1(
            input, candidate, product, &why);
    BOOST_CHECK(
        status ==
        builder::ProductionParentBuildStatusV1::
            CompleteRelationParentUnavailable);
    BOOST_CHECK(
        why.find("production_authority_or_local_parent_missing") !=
        std::string::npos);
    BOOST_CHECK(
        !rc::kRCStage3RelationClosureAuthorityReady);
    BOOST_CHECK(
        !fp::kRecursiveFixedPointConsensusAuthority);
}

BOOST_AUTO_TEST_CASE(
    streaming_receipt_store_put_for_test_requires_capture)
{
    // Fixture helper for later Built wiring once RoleAudit is honestly green:
    // receipt install is paired to an existing episode capture header.
    rc::RCStage3EpisodeWinnerBundleStoreClearForTest();
    const uint256 header = H(0x44);
    auto receipt = std::make_shared<
        const streaming::StreamingEpisodeClosureReceiptV1>(
        SyntheticStreamingReceiptFixtureV1());
    std::string why;
    BOOST_CHECK(
        !rc::RCStage3EpisodeStreamingReceiptStorePutForTest(
            header, receipt, &why));
    BOOST_CHECK(
        why.find("streaming_receipt_store_capture_missing") !=
        std::string::npos);
    BOOST_CHECK(
        !rc::RCStage3EpisodeStreamingReceiptStoreGet(header));
    rc::RCStage3EpisodeWinnerBundleStoreClearForTest();
}

BOOST_AUTO_TEST_SUITE_END()
