// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>

namespace rc = matmul::v4::rc;
namespace ha = matmul::v4::rc::stage3_hash_air;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_root_chain_tests,
    BasicTestingSetup)

namespace {

uint256 Filled(uint8_t value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

rc::RCStage3SuccinctProof EpisodeStatement(const uint256& digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 77;
    out.public_inputs.n_bits = 0x207fffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = Filled(0x11);
    out.public_inputs.params_commitment = Filled(0x22);
    out.public_inputs.sigma = Filled(0x33);
    out.public_inputs.episode_digest = digest;
    out.public_inputs.target = Filled(0xff);
    out.public_inputs.final_digest = digest;
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(vector_air_round_trip_rejects_every_public_mutation)
{
    const std::vector<uint8_t> values{0, 1, 2, 127, 128, 255};
    const uint256 statement = Filled(0x41);
    const uint256 collection = Filled(0x42);
    rc::RCStage3RootChainVectorPin pin;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3RootChainVectorPin(
            rc::RCStage3RelationEndpoint::
                CoupledDigestBankAndBarriers,
            statement, collection, values, pin, &why), why);
    rc::RCStage3RootChainVectorProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3RootChainVector(
            pin, values, proof, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3RootChainVector(
            pin.endpoint, statement, collection, values,
            pin, proof, &why), why);

    auto changed_values = values;
    changed_values[2] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3RootChainVector(
        pin.endpoint, statement, collection, changed_values,
        pin, proof, &why));
    BOOST_CHECK(!rc::VerifyRCStage3RootChainVector(
        pin.endpoint, Filled(0x43), collection, values,
        pin, proof, &why));
    BOOST_CHECK(!rc::VerifyRCStage3RootChainVector(
        pin.endpoint, statement, Filled(0x44), values,
        pin, proof, &why));

    auto changed_proof = proof;
    BOOST_REQUIRE(!changed_proof.quotient.batch.queries.empty());
    BOOST_REQUIRE(
        !changed_proof.quotient.batch.queries[0].columns.empty());
    changed_proof.quotient.batch.queries[0].columns[0].value =
        rc::gkr_field::Add(
            changed_proof.quotient.batch.queries[0]
                .columns[0].value,
            rc::gkr_field::Fp3::One());
    BOOST_CHECK(!rc::VerifyRCStage3RootChainVector(
        pin.endpoint, statement, collection, values,
        pin, changed_proof, &why));
}

BOOST_AUTO_TEST_CASE(typed_manifests_are_structural_and_order_exact)
{
    std::string why;
    ha::EpisodeDigestManifest episode;
    const std::vector<uint256> roots{Filled(0x51), Filled(0x52)};
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(2, roots, episode, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3EpisodeDigestManifestStructural(
            episode, 2, &why), why);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeDigestManifestStructural(
        episode, 3, &why));
    auto reordered = episode;
    std::swap(reordered.round_roots[0], reordered.round_roots[1]);
    BOOST_CHECK(!rc::ValidateRCStage3EpisodeDigestManifestStructural(
        reordered, 2, &why));

    rc::RCStage3CoupledShape shape;
    shape.barriers = 2;
    shape.transcript_version = rc::ENC_RC_V4;
    ha::CoupledBarrierManifest barrier0;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCoupledBarrierManifest(
            shape.transcript_version, shape.barriers, 0,
            {1, 2, 3, 4}, barrier0, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledBarrierManifestStructural(
            shape, 0, barrier0, &why), why);
    BOOST_CHECK(!rc::ValidateRCStage3CoupledBarrierManifestStructural(
        shape, 1, barrier0, &why));
    auto changed_state = barrier0;
    changed_state.state_bytes[0] ^= 1;
    BOOST_CHECK(!rc::ValidateRCStage3CoupledBarrierManifestStructural(
        shape, 0, changed_state, &why));

    ha::CoupledDigestManifest coupled;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCoupledDigestManifest(
            shape.transcript_version, shape.barriers, Filled(0x61),
            {barrier0.direct.digest, Filled(0x62)}, coupled, &why), why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3CoupledDigestManifestStructural(
            shape, coupled, &why), why);
    auto changed_barrier = coupled;
    changed_barrier.barrier_roots[0] = Filled(0x63);
    BOOST_CHECK(!rc::ValidateRCStage3CoupledDigestManifestStructural(
        shape, changed_barrier, &why));
}

BOOST_AUTO_TEST_CASE(root_chain_audit_is_exact_and_fail_closed_upstream)
{
    const auto audit = rc::CurrentRCStage3RootChainEndpointAudit();
    BOOST_REQUIRE_EQUAL(audit.size(), 8U);
    const std::array<uint16_t, 8> expected{
        23, 24, 47, 48, 49, 50, 51, 52};
    uint32_t local = 0;
    uint32_t producer = 0;
    uint32_t strict = 0;
    for (uint32_t i = 0; i < audit.size(); ++i) {
        BOOST_CHECK_EQUAL(
            static_cast<uint16_t>(audit[i].endpoint), expected[i]);
        local += audit[i].local_relation_complete ? 1U : 0U;
        producer += audit[i].producer_graph_complete ? 1U : 0U;
        strict += audit[i].strict_semantic_complete ? 1U : 0U;
        BOOST_CHECK_EQUAL(
            audit[i].strict_semantic_complete,
            audit[i].local_relation_complete &&
                audit[i].producer_graph_complete);
    }
    BOOST_CHECK_EQUAL(local, 7U);
    BOOST_CHECK_EQUAL(producer, 0U);
    BOOST_CHECK_EQUAL(strict, 0U);
    const auto& digest_inputs = audit.at(5);
    BOOST_CHECK(
        digest_inputs.endpoint ==
        rc::RCStage3RelationEndpoint::
            CoupledDigestBankAndBarriers);
    BOOST_CHECK(digest_inputs.proof_owned_vector_executable);
    BOOST_CHECK(digest_inputs.upstream_relation_equality_executable);
    BOOST_CHECK(digest_inputs.local_relation_complete);
    BOOST_CHECK(!digest_inputs.producer_graph_complete);
    BOOST_CHECK(!rc::kRCStage3GlobalRootChainRecursivelyConsumed);
}

BOOST_AUTO_TEST_CASE(full_episode_digest_root_chain_executes)
{
    if (std::getenv("BTX_RUN_STAGE3_ROOT_CHAIN_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_ROOT_CHAIN_PROVE=1 for the complete "
            "episode digest fixed-program provenance round trip");
        return;
    }
    std::string why;
    ha::EpisodeDigestManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            2, {Filled(0x71), Filled(0x72)}, manifest, &why), why);
    auto statement = EpisodeStatement(manifest.direct.digest);
    // Valid compact target 0x2100ffff.  This is above the fixed fixture
    // digest while still exercising endpoint 25's exact compact decoding.
    statement.public_inputs.n_bits = 0x2100ffffU;
    statement.public_inputs.target.SetNull();
    statement.public_inputs.target.data()[30] = 0xff;
    statement.public_inputs.target.data()[31] = 0xff;

    rc::RCStage3EpisodeDigestRootChainProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeDigestRootChain(
            statement, 2, manifest.round_roots, proof, &why),
        why);

    auto changed = proof;
    changed.manifest.round_roots[0].begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeDigestRootChain(
        statement, 2, changed, &why));

    rc::RCStage3EpisodeHeaderTargetProduct header_target;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeHeaderTargetProduct(
            statement, header_target, &why),
        why);
    rc::RCStage3EpisodeDigestPowCtlProof bridge;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeDigestPowCtl(
            statement, 2, proof, header_target,
            bridge, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeDigestPowCtl(
            statement, 2, proof, header_target,
            bridge, &why),
        why);

    auto digest_root_substitution = bridge;
    digest_root_substitution.digest_lane.pins[0]
        .trace_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeDigestPowCtl(
        statement, 2, proof, header_target,
        digest_root_substitution, &why));

    auto target_root_substitution = bridge;
    target_root_substitution.target_lane
        .producer_product.batch.columns[
            rc::kRCStage3EpisodeHeaderTargetByte]
        .root.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeDigestPowCtl(
        statement, 2, proof, header_target,
        target_root_substitution, &why));

    auto pow_digest_detach = bridge;
    pow_digest_detach.digest_lane
        .consumer_product.batch.columns[
            rc::kRCStage3EpisodePowDigestByte]
        .root.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3EpisodeDigestPowCtl(
        statement, 2, proof, header_target,
        pow_digest_detach, &why));
}

BOOST_AUTO_TEST_CASE(full_coupled_barrier_and_digest_root_chain_executes)
{
    if (std::getenv("BTX_RUN_STAGE3_ROOT_CHAIN_PROVE") == nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_ROOT_CHAIN_PROVE=1 for the complete "
            "coupled barrier/digest provenance round trip");
        return;
    }
    std::string why;
    rc::RCStage3CoupledShape shape;
    shape.barriers = 1;
    shape.transcript_version = rc::ENC_RC_V4;

    ha::CoupledBarrierManifest barrier;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCoupledBarrierManifest(
            shape.transcript_version, shape.barriers, 0,
            {4, 3, 2, 1}, barrier, &why), why);
    ha::CoupledDigestManifest digest;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCoupledDigestManifest(
            shape.transcript_version, shape.barriers,
            Filled(0x81), {barrier.direct.digest},
            digest, &why), why);

    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Coupled;
    statement.public_inputs.height = 88;
    statement.public_inputs.coupled_profile = 4;
    statement.public_inputs.transcript_version = shape.transcript_version;
    statement.public_inputs.header_commitment = Filled(0x82);
    statement.public_inputs.params_commitment = Filled(0x83);
    statement.public_inputs.sigma = Filled(0x84);
    statement.public_inputs.coupled_digest = digest.direct.digest;
    statement.public_inputs.final_digest = digest.direct.digest;

    rc::RCStage3CoupledRootChainProof proof;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3CoupledRootChain(
            statement, shape, Filled(0x81),
            {{4, 3, 2, 1}}, proof, &why),
        why);
    auto wrong_outer = statement;
    wrong_outer.public_inputs.coupled_digest.begin()[0] ^= 1;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        wrong_outer, shape, proof, &why));
    auto wrong_barrier = proof;
    wrong_barrier.barriers[0].manifest.barrier_index = 1;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_barrier, &why));

    auto wrong_barrier_value = proof;
    wrong_barrier_value.barriers[0].manifest.state_bytes[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_barrier_value, &why));

    auto wrong_bank_root = proof;
    wrong_bank_root.digest_manifest.bank_root.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_bank_root, &why));

    auto wrong_barrier_root = proof;
    wrong_barrier_root.digest_manifest
        .barrier_roots[0].begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_barrier_root, &why));

    auto wrong_vector_root = proof;
    wrong_vector_root.digest_inputs_pin.value_root.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_vector_root, &why));

    auto wrong_vector_proof = proof;
    wrong_vector_proof.digest_inputs_proof
        .pin_commitment.begin()[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_vector_proof, &why));

    auto wrong_digest_manifest = proof;
    wrong_digest_manifest.digest_manifest
        .direct.preimage[0] ^= 1U;
    BOOST_CHECK(!rc::VerifyRCStage3CoupledRootChain(
        statement, shape, wrong_digest_manifest, &why));
}

BOOST_AUTO_TEST_SUITE_END()
