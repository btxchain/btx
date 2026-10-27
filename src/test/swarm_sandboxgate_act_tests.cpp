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

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_act_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_worker_is_not_granted_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_GRANTED");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_worker_is_not_granted)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_GRANTED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(models_prefix_matches_models_a_and_not_models)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);

    BOOST_REQUIRE(!plane.Act("w-1", "models", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(equal_prefix_is_not_a_strict_prefix)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(prefix_match_is_bytewise)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "model", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);

    modelnet::SwarmSandboxGate other;
    BOOST_REQUIRE(other.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!other.Act("w-1", "modelsX", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(other.action_count() == 0);
    BOOST_REQUIRE(!other.Act("w-1", "weight", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    ExpectQuiet(plane);
    ExpectQuiet(other);
}

BOOST_AUTO_TEST_CASE(empty_path_is_denied_before_capability)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_capability_is_capability_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "CAPABILITY");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(missing_capability_is_not_acted_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read", "stat"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "write", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_ACTED");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "Read", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_ACTED");
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "stat", int64_t{11}, err));
    BOOST_REQUIRE(plane.action_count() == 2);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(any_live_matching_grant_can_authorize)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> read_caps{"read"};
    const std::vector<std::string> write_caps{"write"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", read_caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "models/a/", write_caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a/file", "read", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.Act("w-1", "models/a/file", "write", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!plane.Act("w-1", "models/a/file", "stat", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_ACTED");
    BOOST_REQUIRE(plane.action_count() == 2);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(another_workers_grant_does_not_authorize)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-2", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "NOT_GRANTED");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(plane.action_count() == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(successful_act_leaves_launched_false)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{1}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/b", "read", int64_t{2}, err));
    BOOST_REQUIRE(plane.action_count() == 2);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
