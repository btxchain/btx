// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>

namespace rc = matmul::v4::rc;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_round_roots_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(uint8_t value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

rc::RCStage3SuccinctProof Statement(const uint256& episode_digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 91;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = Filled(0x11);
    out.public_inputs.params_commitment = Filled(0x22);
    out.public_inputs.sigma = Filled(0x33);
    out.public_inputs.target = Filled(0xff);
    out.public_inputs.episode_digest = episode_digest;
    out.public_inputs.final_digest = episode_digest;
    return out;
}

rc::RCStage3EpisodeRoundRootProducerProduct StructuralProduct(
    const rc::RCStage3SuccinctProof& statement,
    const ha::EpisodeDigestManifest& digest,
    const std::vector<ha::TileTreeManifest>& trees)
{
    rc::RCStage3EpisodeRoundRootProducerProduct out;
    out.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    out.expected_rounds = trees.size();
    out.digest_manifest_commitment = digest.commitment;
    out.rounds.resize(trees.size());
    for (uint32_t i = 0; i < trees.size(); ++i) {
        auto& round = out.rounds[i];
        round.round_index = i;
        round.tree_manifest = trees[i];
        round.hash_bundle.endpoint =
            rc::RCStage3RelationEndpoint::EpisodeTileTreeRoot;
        round.hash_bundle.statement_commitment =
            out.statement_commitment;
        round.hash_bundle.manifest_commitment =
            trees[i].commitment;
    }
    out.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            out);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_round_schedule_rejects_omission_reorder_and_root_substitution)
{
    std::string why;
    std::vector<ha::TileTreeManifest> trees(2);
    BOOST_REQUIRE(ha::BuildTileTreeManifest(
        {1, 2, 3}, 4, trees[0], &why));
    BOOST_REQUIRE(ha::BuildTileTreeManifest(
        {4, 5, 6}, 4, trees[1], &why));
    ha::EpisodeDigestManifest digest;
    BOOST_REQUIRE(ha::BuildEpisodeDigestManifest(
        2, {trees[0].root, trees[1].root}, digest, &why));
    const auto statement = Statement(digest.direct.digest);
    const auto product = StructuralProduct(statement, digest, trees);
    BOOST_REQUIRE_MESSAGE(
        rc::ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, 2, digest, product, &why),
        why);

    auto omitted = product;
    omitted.rounds.pop_back();
    omitted.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            omitted);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, 2, digest, omitted, &why));

    auto reordered = product;
    std::swap(reordered.rounds[0], reordered.rounds[1]);
    reordered.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            reordered);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, 2, digest, reordered, &why));

    auto substituted = product;
    substituted.rounds[0].tree_manifest.root = Filled(0x77);
    substituted.rounds[0].tree_manifest.commitment =
        ha::CommitTileTreeManifest(
            substituted.rounds[0].tree_manifest);
    substituted.rounds[0].hash_bundle.manifest_commitment =
        substituted.rounds[0].tree_manifest.commitment;
    substituted.collection_commitment =
        rc::ComputeRCStage3EpisodeRoundRootProducerCollectionCommitment(
            substituted);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, 2, digest, substituted, &why));

    auto detached_statement = product;
    detached_statement.rounds[0]
        .hash_bundle.statement_commitment = Filled(0x88);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeRoundRootProducerSchedule(
            statement, 2, digest, detached_statement, &why));
}

BOOST_AUTO_TEST_CASE(audit_distinguishes_local_from_transitive_completion)
{
    const auto audit =
        rc::CurrentRCStage3EpisodeRoundRootProducerAudit();
    BOOST_CHECK(
        audit.endpoint ==
        rc::RCStage3RelationEndpoint::EpisodeDigestRoundRoots);
    BOOST_CHECK(audit.verifier_ordered_round_schedule);
    BOOST_CHECK(audit.all_tile_tree_hash_children_executed);
    BOOST_CHECK(audit.tile_root_to_digest_vector_equality);
    BOOST_CHECK(audit.immediate_producer_link_executable);
    BOOST_CHECK(audit.proof_owned_digest_vector_executed);
    BOOST_CHECK(
        audit.tile_root_to_round_vector_ctl_executable);
    BOOST_CHECK(
        audit.round_root_to_digest_preimage_ctl_executable);
    BOOST_CHECK(audit.downstream_digest_chain_composable);
    BOOST_CHECK(audit.local_relation_complete);
    BOOST_CHECK(!audit.upstream_tile_stream_equality);
    BOOST_CHECK(!audit.recursively_consumed);
    BOOST_CHECK(!audit.transitively_complete);
    BOOST_CHECK(!audit.remaining.empty());
}

BOOST_AUTO_TEST_CASE(full_proof_product_executes_and_mutations_reject)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_EPISODE_ROUND_ROOTS_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_EPISODE_ROUND_ROOTS_PROVE=1 for "
            "the complete tile-tree producer/root-vector quotient round trip");
        return;
    }

    std::string why;
    ha::TileTreeManifest tree;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildTileTreeManifest({}, 32, tree, &why), why);
    ha::EpisodeDigestManifest digest;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            1, {tree.root}, digest, &why), why);
    const auto statement = Statement(digest.direct.digest);
    rc::RCStage3EpisodeDigestRootChainProof root_chain;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeDigestRootChain(
            statement, 1, {tree.root}, root_chain, &why),
        why);
    rc::RCStage3EpisodeRoundRootProducerProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeRoundRootProducerProduct(
            statement, 1, root_chain, {tree}, product, &why),
        why);
    rc::RCStage3EpisodeRoundRootDigestCtlProof digest_ctl;
    rc::RCStage3EpisodeTileTreeRootVectorCtlProof root_ctl;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeTileTreeRootVectorCtl(
            statement, 1, root_chain, product,
            root_ctl, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeTileTreeRootVectorCtl(
            statement, 1, root_chain, product,
            root_ctl, &why),
        why);
    auto changed_root_ctl = root_ctl;
    changed_root_ctl.consumer_product.batch.columns[
        rc::kRCStage3RootChainValue].root = Filled(0x72);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeTileTreeRootVectorCtl(
            statement, 1, root_chain, product,
            changed_root_ctl, &why));

    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            digest_ctl, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            digest_ctl, &why),
        why);

    auto changed_ctl_pin = digest_ctl;
    changed_ctl_pin.bridge_pin.value_root = Filled(0x76);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            changed_ctl_pin, &why));

    auto changed_ctl_producer_root = digest_ctl;
    changed_ctl_producer_root.producer_product.batch.columns[
        rc::kRCStage3RootChainValue].root = Filled(0x75);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            changed_ctl_producer_root, &why));

    auto changed_ctl_consumer_root = digest_ctl;
    changed_ctl_consumer_root.consumer_product.batch.columns[
        rc::kRCStage3EpisodeDigestBridgeExport].root =
            Filled(0x74);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            changed_ctl_consumer_root, &why));

    auto changed_ctl_transcript = digest_ctl;
    changed_ctl_transcript.pins[0].trace_commitment =
        Filled(0x73);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootDigestCtl(
            statement, 1, root_chain, product,
            changed_ctl_transcript, &why));

    auto changed_hash = product;
    BOOST_REQUIRE(
        !changed_hash.rounds[0].hash_bundle.proofs.empty());
    auto& quotient =
        changed_hash.rounds[0].hash_bundle.proofs[0].quotient;
    BOOST_REQUIRE(!quotient.batch.queries.empty());
    BOOST_REQUIRE(!quotient.batch.queries[0].columns.empty());
    quotient.batch.queries[0].columns[0].value =
        gf::Add(
            quotient.batch.queries[0].columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootProducerProduct(
            statement, 1, digest, root_chain.round_roots_pin,
            root_chain.round_roots_proof,
            changed_hash, &why));

    auto changed_vector = root_chain.round_roots_proof;
    BOOST_REQUIRE(!changed_vector.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !changed_vector.quotient.batch.queries[0].columns.empty());
    changed_vector.quotient.batch.queries[0].columns[0].value =
        gf::Add(
            changed_vector.quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeRoundRootProducerProduct(
            statement, 1, digest, root_chain.round_roots_pin,
            changed_vector,
            product, &why));
}

BOOST_AUTO_TEST_SUITE_END()
