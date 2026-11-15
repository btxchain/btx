// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_ckpttrust_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(claim_rules)
{
    modelnet::SwarmCkptTrust trust;
    std::string err = "stale";

    BOOST_CHECK(!trust.bytes_moved());
    BOOST_CHECK(!trust.Claim("", true, true, err));
    BOOST_CHECK_EQUAL(err, "CHECKPOINT");
    BOOST_CHECK(!trust.trusted(""));
    BOOST_CHECK(!trust.bytes_moved());

    BOOST_CHECK(!trust.Claim("ckpt-recipe", false, true, err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    BOOST_CHECK(!trust.trusted("ckpt-recipe"));
    BOOST_CHECK(!trust.bytes_moved());

    BOOST_CHECK(!trust.Claim("ckpt-recipe", true, true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!trust.trusted("ckpt-recipe"));
    BOOST_CHECK(!trust.bytes_moved());

    err = "stale";
    BOOST_REQUIRE(trust.Claim("ckpt-fresh", true, true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(trust.trusted("ckpt-fresh"));
    BOOST_CHECK(!trust.bytes_moved());
}

BOOST_AUTO_TEST_SUITE_END()
