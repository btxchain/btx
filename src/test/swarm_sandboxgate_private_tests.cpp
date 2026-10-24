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

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_private_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(granted_private_prefix_returns_private_data_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "private/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.granted("w-1"));

    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "read", int64_t{11}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(!plane.launched());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(private_path_is_refused_before_an_empty_capability)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "private/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "", int64_t{10}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(private_path_without_a_matching_prefix_is_denied)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(a_shorter_prefix_that_covers_a_private_path_is_private_data)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "pri", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(a_non_private_prefix_on_the_same_worker_still_acts)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "private/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));

    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 0);

    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);

    BOOST_REQUIRE(!plane.Act("w-1", "private/other", "read", int64_t{12}, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(private_prefix_does_not_match_a_different_byte_sequence)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "private/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "privateX/a", "read", int64_t{10}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
