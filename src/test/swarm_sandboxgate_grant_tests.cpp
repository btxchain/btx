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

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_grant_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_worker_is_worker_and_stores_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(!plane.Grant("", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(err == "WORKER");
    BOOST_REQUIRE(!plane.granted(""));
    BOOST_REQUIRE(!plane.granted("w-1"));
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.network_permitted("", int64_t{0}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_prefix_is_path_and_stores_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(!plane.Grant("w-1", "", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(err == "PATH");
    BOOST_REQUIRE(!plane.granted("w-1"));
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{0}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(negative_until_is_timeout_and_stores_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(!plane.Grant("w-1", "models/", caps, true, int64_t{-1}, err));
    BOOST_REQUIRE(err == "TIMEOUT");
    BOOST_REQUIRE(!plane.granted("w-1"));
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_capabilities_is_capability_and_stores_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps;

    BOOST_REQUIRE(!plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(err == "CAPABILITY");
    BOOST_REQUIRE(!plane.granted("w-1"));
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(refusal_order_is_worker_then_path_then_timeout_then_capability)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> empty_caps;

    BOOST_REQUIRE(!plane.Grant("", "", empty_caps, false, int64_t{-5}, err));
    BOOST_REQUIRE(err == "WORKER");
    BOOST_REQUIRE(!plane.Grant("w-1", "", empty_caps, false, int64_t{-5}, err));
    BOOST_REQUIRE(err == "PATH");
    BOOST_REQUIRE(!plane.Grant("w-1", "models/", empty_caps, false, int64_t{-5}, err));
    BOOST_REQUIRE(err == "TIMEOUT");
    BOOST_REQUIRE(!plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(usable_grant_stores_and_clears_err)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(!plane.granted("w-2"));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{99}));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{100}));
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(zero_until_is_stored)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{0}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{0}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_capabilities_network_and_until)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> first{"read"};
    const std::vector<std::string> second{"write"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", first, false, int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.Grant("w-1", "models/", second, true, int64_t{500}, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{50}));
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{50}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "write", int64_t{50}, err));
    BOOST_REQUIRE(err == "NOT_ACTED");
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", int64_t{100}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(a_worker_may_hold_more_than_one_prefix)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> read_caps{"read"};
    const std::vector<std::string> write_caps{"write"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", read_caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "weights/", write_caps, true, int64_t{80}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{79}));
    BOOST_REQUIRE(!plane.network_permitted("w-1", int64_t{80}));

    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(plane.Act("w-1", "weights/b", "write", int64_t{10}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "write", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_ACTED");
    BOOST_REQUIRE(plane.action_count() == 2);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(two_workers_keep_separate_grants)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-2", "models/", caps, false, int64_t{40}, err));
    BOOST_REQUIRE(plane.granted("w-1"));
    BOOST_REQUIRE(plane.granted("w-2"));
    BOOST_REQUIRE(plane.network_permitted("w-1", int64_t{10}));
    BOOST_REQUIRE(!plane.network_permitted("w-2", int64_t{10}));
    BOOST_REQUIRE(!plane.Grant("w-2", "models/", caps, true, int64_t{90}, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(!plane.network_permitted("w-2", int64_t{10}));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(failed_grant_does_not_block_a_later_usable_grant)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> empty_caps;
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(!plane.Grant("w-1", "models/", empty_caps, false, int64_t{100}, err));
    BOOST_REQUIRE(err == "CAPABILITY");
    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
