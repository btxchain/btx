// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_preimagelen.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_preimagelen_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_claim)
{
    std::string err;
    const modelnet::SwarmPreimageLen claim{"", 0, false};
    const modelnet::SwarmPreimageLenResult result = modelnet::SwarmNotePreimageLength(claim, err);
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "CLAIM");
    BOOST_CHECK_EQUAL(err, "CLAIM");
}

BOOST_AUTO_TEST_CASE(length_not_32)
{
    std::string err;
    const modelnet::SwarmPreimageLen claim{"claim-1", 16, false};
    const modelnet::SwarmPreimageLenResult result = modelnet::SwarmNotePreimageLength(claim, err);
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CLAIMED");
    BOOST_CHECK_EQUAL(err, "NOT_CLAIMED");
}

BOOST_AUTO_TEST_CASE(want_claim_held)
{
    std::string err;
    const modelnet::SwarmPreimageLen claim{"claim-1", 32, true};
    const modelnet::SwarmPreimageLenResult result = modelnet::SwarmNotePreimageLength(claim, err);
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    std::string err = "stale";
    const modelnet::SwarmPreimageLen claim{"claim-1", 32, false};
    const modelnet::SwarmPreimageLenResult result = modelnet::SwarmNotePreimageLength(claim, err);
    BOOST_CHECK_EQUAL(result.claimed, false);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
