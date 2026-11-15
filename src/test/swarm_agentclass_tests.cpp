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

namespace {

void ExpectIdle(const modelnet::SwarmAgentClass& session)
{
    BOOST_REQUIRE(!session.launched());
    BOOST_REQUIRE(!session.connected());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_agentclass_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_admit_is_task_and_stores_nothing)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";

    BOOST_REQUIRE(!session.Admit("", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!session.Admit("task-1", "", "weights/", int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!session.Admit("task-1", "w-1", "", int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());
    ExpectIdle(session);

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!session.ran());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(second_admit_of_the_same_task_is_replay)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";
    const std::string payload = "alpha-payload";

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(!session.Admit("task-1", "w-1", "other/", int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");

    BOOST_REQUIRE(!session.Work("task-1", "w-1", "other/blob", payload, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "DENIED");
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());

    BOOST_REQUIRE(session.Work("task-1", "w-1", "weights/blob", payload, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(session.ran());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(work_digest_matches_an_independent_hash)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";
    const std::string payload = "alpha-payload";
    const std::string expected = HexStr(Hash(payload));

    BOOST_REQUIRE(expected.size() == 64);
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());
    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(session.Work("task-1", "w-1", "weights/blob", payload, int64_t{10}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(session.ran());
    BOOST_REQUIRE_EQUAL(session.digest(), expected);
    BOOST_REQUIRE(!session.launched());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(net_is_denied_and_does_not_connect)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(!session.Net("w-1", "hid-1", int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "NET_DENIED");
    BOOST_REQUIRE(!session.connected());
    BOOST_REQUIRE(!session.launched());
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(spawn_is_sandbox_absent_and_does_not_launch)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";

    BOOST_REQUIRE(!session.Spawn(err));
    BOOST_REQUIRE_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_REQUIRE(!session.launched());
    BOOST_REQUIRE(!session.connected());

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(!session.Spawn(err));
    BOOST_REQUIRE_EQUAL(err, "SANDBOX_ABSENT");
    BOOST_REQUIRE(!session.launched());
    BOOST_REQUIRE(!session.ran());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(private_path_is_private_data_and_is_not_hashed)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";
    const std::string payload = "sealed-bytes";
    const std::string would_hash = HexStr(Hash(payload));

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "private/", int64_t{100}, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!session.Private("w-1", payload, int64_t{10}, err));
    BOOST_REQUIRE_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());
    BOOST_REQUIRE(session.digest() != would_hash);
    BOOST_REQUIRE(!session.launched());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_CASE(work_at_until_ms_is_expired_and_is_not_hashed)
{
    modelnet::SwarmAgentClass session;
    std::string err = "prior";
    const std::string payload = "alpha-payload";
    const std::string would_hash = HexStr(Hash(payload));

    BOOST_REQUIRE(session.Admit("task-1", "w-1", "weights/", int64_t{100}, err));
    BOOST_REQUIRE(!session.Work("task-1", "w-1", "weights/blob", payload, int64_t{100}, err));
    BOOST_REQUIRE_EQUAL(err, "EXPIRED");
    BOOST_REQUIRE(!session.ran());
    BOOST_REQUIRE(session.digest().empty());
    BOOST_REQUIRE(session.digest() != would_hash);
    BOOST_REQUIRE(!session.launched());
    ExpectIdle(session);
}

BOOST_AUTO_TEST_SUITE_END()
