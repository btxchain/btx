// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentacct.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agentacct_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(charge_adds_both_totals)
{
    modelnet::SwarmAgentAcct acct;
    std::string err = "prior";
    BOOST_CHECK(!acct.Charge("", 1, 1, err));
    BOOST_CHECK_EQUAL(err, "AGENT");
    BOOST_CHECK_EQUAL(acct.Threads(""), 0);
    BOOST_CHECK_EQUAL(acct.Memory(""), 0);

    BOOST_CHECK(!acct.Charge("alpha", -1, 8, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK(!acct.Charge("alpha", 1, -8, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 0);

    BOOST_REQUIRE(acct.Charge("alpha", 4, 512, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 4);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 512);

    BOOST_REQUIRE(acct.Charge("alpha", 2, 128, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 6);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 640);
    BOOST_CHECK_EQUAL(acct.Threads("beta"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("beta"), 0);
}

BOOST_AUTO_TEST_CASE(cap_refusal_leaves_the_old_total)
{
    modelnet::SwarmAgentAcct acct;
    std::string err = "prior";
    BOOST_REQUIRE(acct.Charge("alpha", 40, 1000, err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!acct.Charge("alpha", 25, 1, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 40);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000);

    BOOST_CHECK(!acct.Charge("alpha", 1, 16000, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 40);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000);

    BOOST_CHECK(!acct.Charge("gamma", 65, 0, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(acct.Threads("gamma"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("gamma"), 0);

    BOOST_CHECK(!acct.Charge("gamma", 0, 16385, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(acct.Threads("gamma"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("gamma"), 0);

    BOOST_REQUIRE(acct.Charge("alpha", 24, 15384, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 64);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 16384);

    BOOST_CHECK(!acct.Charge("alpha", 1, 0, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK(!acct.Charge("alpha", 0, 1, err));
    BOOST_CHECK_EQUAL(err, "CAPPED");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 64);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 16384);

    BOOST_REQUIRE(acct.Charge("beta", 64, 16384, err));
    BOOST_CHECK_EQUAL(acct.Threads("beta"), 64);
    BOOST_CHECK_EQUAL(acct.Memory("beta"), 16384);
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 64);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000 + 15384);
}

BOOST_AUTO_TEST_CASE(release_subtracts_and_refuses_over_release)
{
    modelnet::SwarmAgentAcct acct;
    std::string err = "prior";
    BOOST_REQUIRE(acct.Charge("alpha", 10, 1000, err));

    BOOST_CHECK(!acct.Release("alpha", 11, 1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000);

    BOOST_CHECK(!acct.Release("alpha", 1, 1001, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000);

    BOOST_CHECK(!acct.Release("alpha", -1, 1, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 10);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 1000);

    BOOST_REQUIRE(acct.Release("alpha", 4, 250, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 6);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 750);

    BOOST_REQUIRE(acct.Release("alpha", 6, 750, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 0);

    BOOST_CHECK(!acct.Release("alpha", 1, 0, err));
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(acct.Threads("alpha"), 0);
    BOOST_CHECK_EQUAL(acct.Memory("alpha"), 0);
}

BOOST_AUTO_TEST_SUITE_END()
