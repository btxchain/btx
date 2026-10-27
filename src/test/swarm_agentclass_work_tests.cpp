// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentclass/swarm_agentclass.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <util/strencodings.h>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_agentclass_work_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(work_hashes_the_payload_after_the_sandbox_allows_it)
{
    modelnet::SwarmAgentClass agent;
    std::string err = "prior";
    BOOST_REQUIRE(agent.Admit("task-1", "worker-1", "models/", 1000, err));
    BOOST_CHECK(err.empty());

    const std::string payload = "abc";
    BOOST_REQUIRE(agent.Work("task-1", "worker-1", "models/job", payload, 999, err));
    BOOST_CHECK_EQUAL(agent.digest(), HexStr(Hash(payload)));
    BOOST_CHECK(agent.ran());
    BOOST_CHECK(!agent.launched());
    BOOST_CHECK(!agent.connected());

    BOOST_CHECK(!agent.Work("task-1", "worker-1", "models/job", payload, 1000, err));
    BOOST_CHECK_EQUAL(err, "EXPIRED");
    BOOST_CHECK(!agent.launched());
}

BOOST_AUTO_TEST_SUITE_END()
