// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_presence.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_presence_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id_is_node)
{
    modelnet::SwarmLocalPresenceRequest presence{"", 12, false, false};
    std::string err;
    const modelnet::SwarmPresenceResult result = modelnet::SwarmAcceptPresenceLocal(presence, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK_EQUAL(err, "NODE");
    BOOST_CHECK_EQUAL(result.kept, 0);
}

BOOST_AUTO_TEST_CASE(negative_rtt_is_range)
{
    modelnet::SwarmLocalPresenceRequest presence{"n1", -1, false, false};
    std::string err;
    const modelnet::SwarmPresenceResult result = modelnet::SwarmAcceptPresenceLocal(presence, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "RANGE");
    BOOST_CHECK_EQUAL(err, "RANGE");
    BOOST_CHECK_EQUAL(result.kept, 0);
}

BOOST_AUTO_TEST_CASE(want_connect_is_held)
{
    modelnet::SwarmLocalPresenceRequest presence{"n1", 12, true, true};
    std::string err;
    const modelnet::SwarmPresenceResult result = modelnet::SwarmAcceptPresenceLocal(presence, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK_EQUAL(result.kept, 1);
}

BOOST_AUTO_TEST_CASE(local_presence_is_noted)
{
    modelnet::SwarmLocalPresenceRequest presence{"n1", 12, false, false};
    std::string err = "stale";
    const modelnet::SwarmPresenceResult result = modelnet::SwarmAcceptPresenceLocal(presence, err);
    BOOST_CHECK(!result.connected);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK_EQUAL(result.kept, 1);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
