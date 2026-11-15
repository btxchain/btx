// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_watchstate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_watchstate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_channel_is_channel)
{
    modelnet::SwarmWatchState watch{"", false, false, false};
    std::string err;
    const modelnet::SwarmWatchStateResult result = modelnet::SwarmWatchChannel(watch, err);
    BOOST_CHECK(!result.penalized);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(stale_is_stale)
{
    modelnet::SwarmWatchState watch{"ch-1", true, false, false};
    std::string err;
    const modelnet::SwarmWatchStateResult result = modelnet::SwarmWatchChannel(watch, err);
    BOOST_CHECK(!result.penalized);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "STALE");
    BOOST_CHECK_EQUAL(err, "STALE");
}

BOOST_AUTO_TEST_CASE(want_penalty_is_held)
{
    modelnet::SwarmWatchState watch{"ch-1", false, true, false};
    std::string err;
    const modelnet::SwarmWatchStateResult result = modelnet::SwarmWatchChannel(watch, err);
    BOOST_CHECK(!result.penalized);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_watch_is_noted)
{
    modelnet::SwarmWatchState watch{"ch-1", false, false, false};
    std::string err = "prior";
    const modelnet::SwarmWatchStateResult result = modelnet::SwarmWatchChannel(watch, err);
    BOOST_CHECK(!result.penalized);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.secp_penalty);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
