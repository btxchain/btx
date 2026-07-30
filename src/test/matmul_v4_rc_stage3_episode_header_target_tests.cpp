// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

namespace rc = matmul::v4::rc;

namespace {

uint256 H(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Episode;
    out.public_inputs.height = 17;
    out.public_inputs.n_bits = 0x1d00ffffU;
    out.public_inputs.episode_profile = 2;
    out.public_inputs.transcript_version = rc::ENC_RC_V4;
    out.public_inputs.header_commitment = H(0x11);
    out.public_inputs.params_commitment = H(0x22);
    out.public_inputs.sigma = H(0x33);
    out.public_inputs.episode_digest = H(0x44);
    out.public_inputs.target.SetNull();
    out.public_inputs.target.data()[26] = 0xff;
    out.public_inputs.target.data()[27] = 0xff;
    return out;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_header_target_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(compact_target_and_public_vector_round_trip)
{
    const auto statement = Statement();
    rc::RCStage3EpisodeHeaderTargetProduct product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        (rc::ProveRCStage3EpisodeHeaderTargetProduct(
            statement, product, &why)),
        why);
    BOOST_CHECK_MESSAGE(
        (rc::VerifyRCStage3EpisodeHeaderTargetProduct(
            statement,
            statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target,
            product, &why)),
        why);

    auto wrong_target = statement.public_inputs.target;
    wrong_target.data()[0] = 1;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeHeaderTargetProduct(
            statement, statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits, wrong_target,
            product, &why));

    auto detached = product;
    detached.public_memory_manifest.address_stride = 2;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeHeaderTargetProduct(
            statement, statement.public_inputs.header_commitment,
            statement.public_inputs.n_bits,
            statement.public_inputs.target, detached, &why));

    const auto audit =
        rc::CurrentRCStage3EpisodeHeaderTargetAudit();
    BOOST_CHECK(audit.local_relation_complete);
    BOOST_CHECK(audit.producer_provenance_complete);
    BOOST_CHECK(audit.semantic_complete);
    BOOST_CHECK(!audit.recursively_consumed);
}

BOOST_AUTO_TEST_CASE(invalid_compact_encodings_reject)
{
    auto statement = Statement();
    rc::RCStage3EpisodeHeaderTargetPin pin;
    std::string why;
    statement.public_inputs.n_bits = 0x1d80ffffU;
    BOOST_CHECK(
        !rc::BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, &why));
    statement.public_inputs.n_bits = 0;
    BOOST_CHECK(
        !rc::BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, &why));

    statement = Statement();
    statement.public_inputs.n_bits = 0x220000ffU;
    statement.public_inputs.target.SetNull();
    statement.public_inputs.target.data()[31] = 0xff;
    BOOST_CHECK(
        rc::BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, &why));

    statement.public_inputs.n_bits = 0x22000100U;
    BOOST_CHECK(
        !rc::BuildRCStage3EpisodeHeaderTargetPin(
            statement, pin, &why));
}

BOOST_AUTO_TEST_SUITE_END()
