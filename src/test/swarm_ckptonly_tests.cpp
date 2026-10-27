// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptonly.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ckptonly_tests, BasicTestingSetup)

static modelnet::SwarmCkptOnly NotedClaim()
{
    modelnet::SwarmCkptOnly claim;
    claim.claim_id = "claim-1";
    claim.checkpoint_only = false;
    claim.want_trust = false;
    return claim;
}

BOOST_AUTO_TEST_CASE(empty_claim_is_claim)
{
    modelnet::SwarmCkptOnly claim = NotedClaim();
    claim.claim_id.clear();
    claim.checkpoint_only = true;
    claim.want_trust = true;
    std::string err = "prior";
    const modelnet::SwarmCkptOnlyResult result = modelnet::SwarmNoteCkptOnly(claim, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(checkpoint_only_is_not_trust)
{
    modelnet::SwarmCkptOnly claim = NotedClaim();
    claim.checkpoint_only = true;
    claim.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmCkptOnlyResult result = modelnet::SwarmNoteCkptOnly(claim, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "NOT_TRUST");
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
}

BOOST_AUTO_TEST_CASE(want_trust_is_held)
{
    modelnet::SwarmCkptOnly claim = NotedClaim();
    claim.want_trust = true;
    claim.checkpoint_only = false;
    std::string err = "prior";
    const modelnet::SwarmCkptOnlyResult result = modelnet::SwarmNoteCkptOnly(claim, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted_when_neither)
{
    modelnet::SwarmCkptOnly claim = NotedClaim();
    claim.checkpoint_only = false;
    claim.want_trust = false;
    std::string err = "prior";
    const modelnet::SwarmCkptOnlyResult result = modelnet::SwarmNoteCkptOnly(claim, err);
    BOOST_CHECK(!result.trusted);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
