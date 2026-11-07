// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sandboxgate/swarm_sandboxgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

void ExpectQuiet(const modelnet::SwarmSandboxGate& plane)
{
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.automatic_spend() == "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_run_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(run_is_sandbox_absent_and_launched_stays_false)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Run("w-1", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(unknown_worker_is_sandbox_absent)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Run("w-missing", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.Run("", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(run_after_grant_and_act_is_still_sandbox_absent)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE(plane.action_count() == 1);

    BOOST_REQUIRE(!plane.Run("w-1", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{10}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(repeated_run_stays_false)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Run("w-1", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.Run("w-1", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.Run("w-2", err));
    BOOST_REQUIRE(err == "SANDBOX_ABSENT");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
