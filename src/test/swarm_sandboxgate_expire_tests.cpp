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

BOOST_FIXTURE_TEST_SUITE(swarm_sandboxgate_expire_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(now_equal_until_minus_one_acts_and_now_equal_until_is_expired)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};
    const int64_t until = 100;

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, until, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", until - 1, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(plane.network_permitted("w-1", until - 1));
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", until - 1, err));
    BOOST_REQUIRE(err.empty());

    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", until, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.network_permitted("w-1", until));
    BOOST_REQUIRE(!plane.Net("w-1", "hid-1", until, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(!plane.connected());
    BOOST_REQUIRE(!plane.launched());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(now_past_until_stays_expired_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", int64_t{101}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(plane.granted("w-1"));
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(zero_deadline_expires_at_zero_and_acts_before_it)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{0}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{-1}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.Act("w-1", "models/b", "read", int64_t{0}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(plane.Net("w-1", "hid-1", int64_t{-1}, err));
    BOOST_REQUIRE(!plane.Net("w-1", "hid-1", int64_t{0}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(a_non_matching_path_is_denied_when_other_grants_are_expired)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "weights/a", "read", int64_t{100}, err));
    BOOST_REQUIRE(err == "DENIED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(one_live_match_keeps_the_action_when_another_match_is_expired)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "m", caps, false, int64_t{200}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Act("w-1", "models/a", "read", int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", int64_t{200}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(a_separate_prefix_with_a_later_deadline_still_acts)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(plane.Grant("w-1", "weights/", caps, false, int64_t{200}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "models/a", "read", int64_t{100}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 0);
    BOOST_REQUIRE(plane.Act("w-1", "weights/b", "read", int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.action_count() == 1);
    BOOST_REQUIRE(!plane.Act("w-1", "weights/b", "read", int64_t{200}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 1);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(expired_private_path_is_expired_and_records_nothing)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "private/", caps, false, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Act("w-1", "private/ledger", "", int64_t{100}, err));
    BOOST_REQUIRE(err == "EXPIRED");
    BOOST_REQUIRE(plane.action_count() == 0);
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_CASE(empty_host_at_the_deadline_is_net)
{
    modelnet::SwarmSandboxGate plane;
    std::string err = "prior";
    const std::vector<std::string> caps{"read"};

    BOOST_REQUIRE(plane.Grant("w-1", "models/", caps, true, int64_t{100}, err));
    BOOST_REQUIRE(!plane.Net("w-1", "", int64_t{100}, err));
    BOOST_REQUIRE(err == "NET");
    BOOST_REQUIRE(!plane.connected());
    ExpectQuiet(plane);
}

BOOST_AUTO_TEST_SUITE_END()
