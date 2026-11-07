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

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_net_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_host_is_net_and_does_not_connect)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Net("w-1", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "NET");
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{10}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_host_is_net_before_an_unknown_worker)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Net("", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "NET");
    BOOST_REQUIRE(!plane.Net("w-missing", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "NET");
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(unknown_worker_is_not_granted)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Net("w-missing", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_GRANTED");
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.network_permitted("w-missing", int64_t{10}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(no_network_grant_is_net_denied)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{10}));
    BOOST_REQUIRE(!plane.Net("w-1", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(live_network_grant_permits_and_leaves_connected_false)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{99}));
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", int64_t{99}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Net("w-1", "hid-2", int64_t{1}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.bytes_moved() == 0);
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(one_network_grant_among_two_prefixes_permits)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "weights/", caps, true, int64_t{80}, err));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{79}));
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", int64_t{79}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(another_workers_network_grant_does_not_permit)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-2", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Net("w-2", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE(err == "NET_DENIED");
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(expired_network_grant_with_a_live_other_grant_is_expired)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{200}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "weights/", caps, true, int64_t{50}, err));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{50}));
    BOOST_REQUIRE(!plane.Net("w-1", "hid-1", int64_t{50}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(all_grants_expired_is_expired_before_net_denied)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{40}, err));
    BOOST_REQUIRE(!plane.Net("w-1", "hid-1", int64_t{40}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
