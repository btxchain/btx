// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentclass/swarm_agentclass.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agentclass_spawn_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(network_and_spawn_stay_closed_and_private_data_is_not_hashed)
{
    modelnet::SwarmAgentClass agent;
    std::string err;
    BOOST_REQUIRE(agent.Admit("task-1", "worker-1", "models/", 1000, err));

    BOOST_CHECK(!agent.Net("worker-1", "peer-1", 999, err));
    BOOST_CHECK_EQUAL(err, "NET_DENIED");
    BOOST_CHECK(!agent.connected());

    BOOST_CHECK(!agent.Spawn(err));
    BOOST_CHECK_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_CHECK(!agent.launched());

    modelnet::SwarmAgentClass sealed;
    BOOST_REQUIRE(sealed.Admit("task-2", "worker-2", "private/", 1000, err));
    BOOST_CHECK(!sealed.Private("worker-2", "secret", 999, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(!sealed.ran());
    BOOST_CHECK(sealed.digest().empty());
}

BOOST_AUTO_TEST_SUITE_END()
