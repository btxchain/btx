// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/codes.h>
#include <modelnet/swarm_ckpttrust/limits.h>
#include <modelnet/swarm_ckpttrust/swarm_ckpttrust.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ckpttrust_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_trust_of_the_same_claim_is_replay)
{
    modelnet::SwarmCheckpointTrust plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustNotTrust);
    BOOST_REQUIRE_EQUAL(err, "NOT_TRUST");
    BOOST_REQUIRE(plane.claimed("claim-a"));
    BOOST_REQUIRE(plane.stored_claim("claim-a") == "claim-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.trusted());

    err = "prior";
    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.claimed("claim-a"));
    BOOST_REQUIRE(plane.stored_claim("claim-a") == "claim-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.trusted());
    BOOST_REQUIRE(plane.trusted() == modelnet::kSwarmCheckpointTrustTrusted);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_claim("claim-a") == "claim-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.trusted());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_claim_is_claim_before_replay)
{
    modelnet::SwarmCheckpointTrust plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustNotTrust);
    BOOST_REQUIRE_EQUAL(err, "NOT_TRUST");

    err = "prior";
    BOOST_REQUIRE(!plane.Trust("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustClaim);
    BOOST_REQUIRE_EQUAL(err, "CLAIM");
    BOOST_REQUIRE(plane.stored_claim("claim-a") == "claim-a");
    BOOST_REQUIRE(plane.claim_count() == 1);
    BOOST_REQUIRE(!plane.trusted());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_claim_is_stored)
{
    modelnet::SwarmCheckpointTrust plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustNotTrust);
    BOOST_REQUIRE_EQUAL(err, "NOT_TRUST");

    err = "prior";
    BOOST_REQUIRE(!plane.Trust("claim-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustNotTrust);
    BOOST_REQUIRE_EQUAL(err, "NOT_TRUST");

    err = "prior";
    BOOST_REQUIRE(!plane.Trust("claim-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCheckpointTrustReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.claimed("claim-a"));
    BOOST_REQUIRE(plane.claimed("claim-b"));
    BOOST_REQUIRE(plane.stored_claim("claim-a") == "claim-a");
    BOOST_REQUIRE(plane.stored_claim("claim-b") == "claim-b");
    BOOST_REQUIRE(plane.claim_count() == 2);
    BOOST_REQUIRE(!plane.trusted());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCheckpointTrustBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
