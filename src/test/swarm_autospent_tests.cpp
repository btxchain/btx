// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_autospent.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_autospent_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_spend)
{
    modelnet::SwarmAutoSpent spend;
    spend.spend_id.clear();
    spend.want_set = false;
    std::string err;
    const modelnet::SwarmAutoSpentResult result = modelnet::SwarmKeepAutoSpend(spend, err);
    BOOST_CHECK_EQUAL(result.code, "SPEND");
    BOOST_CHECK_EQUAL(err, "SPEND");
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_set_held)
{
    modelnet::SwarmAutoSpent spend;
    spend.spend_id = "spend-1";
    spend.want_set = true;
    std::string err;
    const modelnet::SwarmAutoSpentResult result = modelnet::SwarmKeepAutoSpend(spend, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmAutoSpent spend;
    spend.spend_id = "spend-2";
    spend.want_set = false;
    std::string err = "stale";
    const modelnet::SwarmAutoSpentResult result = modelnet::SwarmKeepAutoSpend(spend, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.armed);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
