// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <utility>

namespace rc = matmul::v4::rc;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_provenance_graph_tests)

namespace {

const rc::RCStage3ProvenanceEdge* FindEdge(
    const rc::RCStage3ProvenanceGraphAudit& audit,
    rc::RCStage3RelationEndpoint producer,
    rc::RCStage3RelationEndpoint consumer)
{
    const auto& node = audit.nodes.at(
        static_cast<uint16_t>(consumer) - 1U);
    const auto found = std::find_if(
        node.producers.begin(), node.producers.end(),
        [producer](const auto& edge) {
            return edge.producer == producer;
        });
    return found == node.producers.end() ? nullptr : &*found;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_52_node_cut_is_ordered_typed_and_fail_closed)
{
    const auto audit =
        rc::CurrentRCStage3ProvenanceGraphAudit();
    BOOST_REQUIRE_EQUAL(audit.nodes.size(), 52U);
    BOOST_CHECK(audit.exact_52_order);
    BOOST_CHECK(audit.exact_public_roots_1_and_25);
    BOOST_CHECK(audit.every_non_public_node_has_a_producer);
    BOOST_CHECK(
        audit.no_missing_out_of_range_self_or_duplicate_producer);
    BOOST_CHECK(audit.capability_flags_fail_closed);
    BOOST_CHECK_EQUAL(audit.edges, 81U);
    BOOST_CHECK_EQUAL(audit.value_equality_edges, 81U);
    BOOST_CHECK_EQUAL(audit.bounded_composition_edges, 81U);
    BOOST_CHECK_EQUAL(audit.production_composition_edges, 17U);
    BOOST_CHECK_EQUAL(audit.normalized_recursive_edges, 0U);
    BOOST_TEST_MESSAGE(
        "provenance graph edges=" << audit.edges
        << " equality=" << audit.value_equality_edges
        << " bounded=" << audit.bounded_composition_edges
        << " production=" << audit.production_composition_edges
        << " recursive=" << audit.normalized_recursive_edges);
    BOOST_CHECK(!rc::kRCStage3ProvenanceGraphIsConsensusProof);

    for (uint16_t i = 0; i < audit.nodes.size(); ++i) {
        const auto& node = audit.nodes[i];
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(node.endpoint), i + 1U);
        BOOST_CHECK_EQUAL(
            node.public_root, i == 0U || i == 24U);
    }
}

BOOST_AUTO_TEST_CASE(
    known_closed_and_open_cut_edges_are_explicit)
{
    const auto audit =
        rc::CurrentRCStage3ProvenanceGraphAudit();
    const auto* bank_pages_to_root = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::CoupledBankPages,
        rc::RCStage3RelationEndpoint::CoupledBankRoot);
    BOOST_REQUIRE(bank_pages_to_root != nullptr);
    BOOST_CHECK(bank_pages_to_root->value_equality_executable);
    BOOST_CHECK(
        bank_pages_to_root->bounded_composition_executable);
    BOOST_CHECK(
        !bank_pages_to_root->production_composition_executable);

    const auto* bank_root_to_digest = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::CoupledBankRoot,
        rc::RCStage3RelationEndpoint::
            CoupledDigestBankAndBarriers);
    BOOST_REQUIRE(bank_root_to_digest != nullptr);
    BOOST_CHECK(bank_root_to_digest->value_equality_executable);
    BOOST_CHECK(
        bank_root_to_digest->production_composition_executable);

    const auto* barrier_output_to_digest = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::CoupledBarrierOutput,
        rc::RCStage3RelationEndpoint::
            CoupledDigestBankAndBarriers);
    BOOST_REQUIRE(barrier_output_to_digest != nullptr);
    BOOST_CHECK(
        barrier_output_to_digest->production_composition_executable);

    const auto* builder_to_a = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::EpisodeBuilderTrace,
        rc::RCStage3RelationEndpoint::EpisodeGemmOperandA);
    BOOST_REQUIRE(builder_to_a != nullptr);
    BOOST_CHECK(builder_to_a->value_equality_executable);
    BOOST_CHECK(builder_to_a->bounded_composition_executable);
    BOOST_CHECK(!builder_to_a->production_composition_executable);
    BOOST_CHECK(!builder_to_a->construction.empty());

    const auto* extract_to_stream = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::EpisodeExtractOutput,
        rc::RCStage3RelationEndpoint::EpisodeTileTreeStream);
    BOOST_REQUIRE(extract_to_stream != nullptr);
    BOOST_CHECK(
        extract_to_stream->production_composition_executable);

    const std::array<
        std::pair<
            rc::RCStage3RelationEndpoint,
            rc::RCStage3RelationEndpoint>,
        7>
        chain_edges{{
            {
                rc::RCStage3RelationEndpoint::
                    CoupledExtractOutput,
                rc::RCStage3RelationEndpoint::CoupledGemmOperandA,
            },
            {
                rc::RCStage3RelationEndpoint::CoupledBankPages,
                rc::RCStage3RelationEndpoint::CoupledGemmOperandB,
            },
            {
                rc::RCStage3RelationEndpoint::CoupledGemmOutputY,
                rc::RCStage3RelationEndpoint::CoupledExchangeInput,
            },
            {
                rc::RCStage3RelationEndpoint::
                    CoupledPermutationOutput,
                rc::RCStage3RelationEndpoint::CoupledMixInput,
            },
            {
                rc::RCStage3RelationEndpoint::CoupledMixOutput,
                rc::RCStage3RelationEndpoint::CoupledExchangeInput,
            },
            {
                rc::RCStage3RelationEndpoint::CoupledMixOutput,
                rc::RCStage3RelationEndpoint::CoupledExtractInput,
            },
            {
                rc::RCStage3RelationEndpoint::CoupledExchangeOutput,
                rc::RCStage3RelationEndpoint::CoupledExtractInput,
            },
        }};
    for (const auto& [producer, consumer] : chain_edges) {
        const auto* edge =
            FindEdge(audit, producer, consumer);
        BOOST_REQUIRE(edge != nullptr);
        BOOST_CHECK(edge->value_equality_executable);
        BOOST_CHECK(edge->bounded_composition_executable);
        BOOST_CHECK(
            !edge->production_composition_executable);
        BOOST_CHECK(!edge->normalized_recursive_executable);
        BOOST_CHECK(
            edge->remaining.find("production streaming") !=
            std::string::npos);
    }

    const auto* seed_to_chacha = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::EpisodeBuilderSeedChain,
        rc::RCStage3RelationEndpoint::EpisodeExtractChaCha);
    BOOST_REQUIRE(seed_to_chacha != nullptr);
    BOOST_CHECK(seed_to_chacha->value_equality_executable);
    BOOST_CHECK(seed_to_chacha->bounded_composition_executable);

    const auto* chacha_to_scale = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::EpisodeExtractChaCha,
        rc::RCStage3RelationEndpoint::EpisodeExtractScale);
    BOOST_REQUIRE(chacha_to_scale != nullptr);
    BOOST_CHECK(chacha_to_scale->value_equality_executable);
    BOOST_CHECK(chacha_to_scale->bounded_composition_executable);

    const auto* public_to_initial_state = FindEdge(
        audit,
        rc::RCStage3RelationEndpoint::EpisodeDigestHeaderTarget,
        rc::RCStage3RelationEndpoint::CoupledGemmOperandA);
    BOOST_REQUIRE(public_to_initial_state != nullptr);
    BOOST_CHECK(public_to_initial_state->value_equality_executable);
    BOOST_CHECK(
        public_to_initial_state->bounded_composition_executable);
    BOOST_CHECK(
        !public_to_initial_state->
            production_composition_executable);
    BOOST_CHECK(
        !public_to_initial_state->
            normalized_recursive_executable);
    BOOST_CHECK(
        public_to_initial_state->construction.find(
            "coupled_initial_state_product_v1") !=
        std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
