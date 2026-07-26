// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_semantic_status.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_semantic_status_tests,
                         BasicTestingSetup)

BOOST_AUTO_TEST_CASE(exact_52_endpoint_audit_is_ordered_and_fail_closed)
{
    const rc::RCStage3CoupledShape shape =
        rc::MakeRCStage3CoupledShape(
            rc::MakeMediumV3RCCoupParams(),
            rc::MakeMediumV4RCCoupOptions());
    const auto status = rc::CurrentRCStage3SemanticStatus(
        shape, gf::Fp3::FromFp(7), gf::Fp3::FromFp(11), 1);
    BOOST_REQUIRE(status.registry_exact);
    BOOST_REQUIRE_EQUAL(status.registered_endpoints, 52U);
    BOOST_REQUIRE_EQUAL(status.endpoints.size(), 52U);
    for (uint16_t i = 0; i < status.endpoints.size(); ++i) {
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(status.endpoints[i].endpoint),
            i + 1);
    }
    BOOST_CHECK_EQUAL(
        status.local_relation_complete_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        status.producer_provenance_endpoints, 2U);
    BOOST_CHECK_EQUAL(status.semantic_complete_endpoints, 2U);
    BOOST_CHECK_EQUAL(status.recursively_consumed_endpoints, 0U);
    BOOST_CHECK_EQUAL(status.complete_roles, 0U);
    BOOST_CHECK_GE(status.canonical_memory_endpoints, 46U);
    for (const auto& endpoint : status.endpoints) {
        BOOST_CHECK_EQUAL(
            endpoint.semantic_complete,
            endpoint.local_relation_complete &&
                endpoint.producer_provenance_complete);
        if (!endpoint.local_relation_complete ||
            !endpoint.producer_provenance_complete ||
            !endpoint.recursively_consumed) {
            BOOST_TEST_MESSAGE(
                "endpoint="
                << static_cast<uint16_t>(endpoint.endpoint)
                << " local=" << endpoint.local_relation_complete
                << " provenance="
                << endpoint.producer_provenance_complete
                << " recursive=" << endpoint.recursively_consumed
                << " remaining=" << endpoint.remaining);
        }
    }
    const auto& wiring = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeWiringCopy) - 1U);
    BOOST_CHECK(wiring.local_relation_complete);
    BOOST_CHECK(!wiring.producer_provenance_complete);
    BOOST_CHECK(!wiring.semantic_complete);
    const auto& builder_params = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderParams) - 1U);
    BOOST_CHECK(builder_params.local_relation_complete);
    BOOST_CHECK(builder_params.producer_provenance_complete);
    BOOST_CHECK(builder_params.semantic_complete);
    BOOST_CHECK(!builder_params.recursively_consumed);
    const auto& barrier_input = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBarrierInput) - 1U);
    BOOST_CHECK(barrier_input.local_relation_complete);
    BOOST_CHECK(!barrier_input.producer_provenance_complete);
    BOOST_CHECK(!barrier_input.semantic_complete);
    const auto& digest_inputs = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::
                CoupledDigestBankAndBarriers) - 1U);
    BOOST_CHECK(digest_inputs.local_relation_complete);
    BOOST_CHECK(!digest_inputs.producer_provenance_complete);
    BOOST_CHECK(!digest_inputs.semantic_complete);
    const auto& seed_chain = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain) - 1U);
    BOOST_CHECK(seed_chain.local_relation_complete);
    BOOST_CHECK(!seed_chain.producer_provenance_complete);
    const auto& operand_xof = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderOperandXof) - 1U);
    BOOST_CHECK(operand_xof.local_relation_complete);
    BOOST_CHECK(!operand_xof.producer_provenance_complete);
    BOOST_CHECK(!operand_xof.semantic_complete);
    const auto& builder_trace = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderTrace) - 1U);
    BOOST_CHECK(builder_trace.local_relation_complete);
    BOOST_CHECK(!builder_trace.producer_provenance_complete);
    BOOST_CHECK(!builder_trace.semantic_complete);
    for (uint16_t endpoint_id = 5; endpoint_id <= 8; ++endpoint_id) {
        const auto& gemm = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(gemm.local_relation_complete);
        BOOST_CHECK(!gemm.producer_provenance_complete);
        BOOST_CHECK(!gemm.semantic_complete);
    }
    for (uint16_t endpoint_id = 10; endpoint_id <= 14; ++endpoint_id) {
        const auto& extract = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(extract.local_relation_complete);
        BOOST_CHECK(!extract.producer_provenance_complete);
        BOOST_CHECK(!extract.semantic_complete);
    }
    for (uint16_t endpoint_id = 16; endpoint_id <= 18; ++endpoint_id) {
        const auto& wiring_endpoint =
            status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(wiring_endpoint.local_relation_complete);
        BOOST_CHECK(
            !wiring_endpoint.producer_provenance_complete);
        BOOST_CHECK(!wiring_endpoint.semantic_complete);
    }
    for (uint16_t endpoint_id = 19; endpoint_id <= 22; ++endpoint_id) {
        const auto& tile = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(tile.local_relation_complete);
        BOOST_CHECK(!tile.producer_provenance_complete);
        BOOST_CHECK(!tile.semantic_complete);
    }
    for (uint16_t endpoint_id = 30; endpoint_id <= 32; ++endpoint_id) {
        const auto& gemm = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(gemm.local_relation_complete);
        BOOST_CHECK(!gemm.producer_provenance_complete);
        BOOST_CHECK(!gemm.semantic_complete);
    }
    for (uint16_t endpoint_id = 27; endpoint_id <= 28; ++endpoint_id) {
        const auto& bank = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(bank.local_relation_complete);
        BOOST_CHECK(!bank.producer_provenance_complete);
        BOOST_CHECK(!bank.semantic_complete);
    }
    for (uint16_t endpoint_id = 34; endpoint_id <= 38; ++endpoint_id) {
        const auto& exchange_or_permutation =
            status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(exchange_or_permutation.local_relation_complete);
        BOOST_CHECK(
            !exchange_or_permutation.producer_provenance_complete);
        BOOST_CHECK(!exchange_or_permutation.semantic_complete);
    }
    for (uint16_t endpoint_id = 39; endpoint_id <= 41; ++endpoint_id) {
        const auto& mix = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(mix.local_relation_complete);
        BOOST_CHECK(!mix.producer_provenance_complete);
        BOOST_CHECK(!mix.semantic_complete);
    }
    for (uint16_t endpoint_id = 42; endpoint_id <= 46; ++endpoint_id) {
        const auto& extract = status.endpoints.at(endpoint_id - 1U);
        BOOST_CHECK(extract.local_relation_complete);
        BOOST_CHECK(!extract.producer_provenance_complete);
        BOOST_CHECK(!extract.semantic_complete);
    }
    const auto& header_target = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeDigestHeaderTarget) - 1U);
    BOOST_CHECK(header_target.local_relation_complete);
    BOOST_CHECK(header_target.producer_provenance_complete);
    BOOST_CHECK(header_target.semantic_complete);
}

BOOST_AUTO_TEST_CASE(production_bank_stream_removes_flat_manifest_local_gap)
{
    const rc::RCStage3CoupledShape shape =
        rc::MakeRCStage3CoupledShape(
            rc::MakeProductionV3RCCoupParams(),
            rc::MakeV3RCCoupOptions());
    const auto status = rc::CurrentRCStage3SemanticStatus(
        shape, gf::Fp3::FromFp(7), gf::Fp3::FromFp(11), 1,
        true);
    BOOST_REQUIRE(status.registry_exact);
    BOOST_CHECK_EQUAL(
        status.local_relation_complete_endpoints, 19U);
    BOOST_CHECK_EQUAL(
        status.producer_provenance_endpoints, 2U);
    BOOST_CHECK_EQUAL(status.semantic_complete_endpoints, 2U);
    const auto& bank_root = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBankRoot) - 1U);
    BOOST_CHECK(bank_root.local_relation_complete);
    BOOST_CHECK(!bank_root.producer_provenance_complete);
    BOOST_CHECK(!bank_root.semantic_complete);
    const auto& barrier_input = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::CoupledBarrierInput) - 1U);
    BOOST_CHECK(!barrier_input.local_relation_complete);
    const auto& operand_xof = status.endpoints.at(
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderOperandXof) - 1U);
    BOOST_CHECK(!operand_xof.local_relation_complete);
    BOOST_CHECK(
        !status.endpoints.at(
            static_cast<uint16_t>(
                rc::RCStage3RelationEndpoint::EpisodeBuilderTrace) - 1U)
             .local_relation_complete);
    for (uint16_t endpoint_id = 5; endpoint_id <= 8; ++endpoint_id) {
        BOOST_CHECK(
            !status.endpoints.at(endpoint_id - 1U)
                 .local_relation_complete);
    }
    for (uint16_t endpoint_id = 10; endpoint_id <= 14; ++endpoint_id) {
        BOOST_CHECK(
            !status.endpoints.at(endpoint_id - 1U)
                 .local_relation_complete);
    }
    for (uint16_t endpoint_id = 16; endpoint_id <= 18; ++endpoint_id) {
        BOOST_CHECK(
            !status.endpoints.at(endpoint_id - 1U)
                 .local_relation_complete);
    }
    for (uint16_t endpoint_id = 30; endpoint_id <= 32; ++endpoint_id) {
        BOOST_CHECK(
            !status.endpoints.at(endpoint_id - 1U)
                 .local_relation_complete);
    }
    for (uint16_t endpoint_id = 27; endpoint_id <= 28; ++endpoint_id) {
        BOOST_CHECK(
            !status.endpoints.at(endpoint_id - 1U)
                 .local_relation_complete);
    }
}

BOOST_AUTO_TEST_SUITE_END()
