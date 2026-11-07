// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_tokgate/swarm_tokgate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectIdle(const modelnet::SwarmTokenGate& plane)
{
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.ttft_ms() == int64_t{-1});
    BOOST_REQUIRE(plane.p50_ms() == int64_t{-1});
    BOOST_REQUIRE(plane.p95_ms() == int64_t{-1});
    BOOST_REQUIRE(!plane.measured());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.bytes_moved() == int64_t{0});
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_tokgate_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_session_is_model_and_stores_nothing)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("", "model-a", err));
    BOOST_REQUIRE(err == "MODEL");
    BOOST_REQUIRE(!plane.open(""));
    BOOST_REQUIRE(!plane.open("model-a"));
    BOOST_REQUIRE(plane.model_id("").empty());
    BOOST_REQUIRE(plane.engine_name("").empty());
    BOOST_REQUIRE(!plane.prompt_stored(""));
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_model_is_model_and_stores_nothing)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("sess-1", "", err));
    BOOST_REQUIRE(err == "MODEL");
    BOOST_REQUIRE(!plane.open("sess-1"));
    BOOST_REQUIRE(plane.model_id("sess-1").empty());
    BOOST_REQUIRE(!plane.prompt_stored("sess-1"));
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(both_empty_is_model)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Open("", "", err));
    BOOST_REQUIRE(err == "MODEL");
    BOOST_REQUIRE(!plane.open(""));
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(open_stores_session_and_stays_idle)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.open("sess-1"));
    BOOST_REQUIRE(plane.model_id("sess-1") == "model-a");
    BOOST_REQUIRE(!plane.open("sess-2"));
    BOOST_REQUIRE(plane.engine_name("sess-1").empty());
    BOOST_REQUIRE(!plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(!plane.running());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_keeps_first_model)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Open("sess-1", "model-b", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.open("sess-1"));
    BOOST_REQUIRE(plane.model_id("sess-1") == "model-a");
    BOOST_REQUIRE(!plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.model_id("sess-1") == "model-a");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_model_after_open_is_model_and_keeps_first)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Open("sess-1", "", err));
    BOOST_REQUIRE(err == "MODEL");
    BOOST_REQUIRE(plane.model_id("sess-1") == "model-a");
    BOOST_REQUIRE(plane.open("sess-1"));
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(two_sessions_stay_separate)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.Open("sess-2", "model-b", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.model_id("sess-1") == "model-a");
    BOOST_REQUIRE(plane.model_id("sess-2") == "model-b");
    BOOST_REQUIRE(!plane.Open("sess-1", "model-c", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.model_id("sess-2") == "model-b");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(blank_check_does_not_trim)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open(" ", "model-a", err));
    BOOST_REQUIRE(plane.open(" "));
    BOOST_REQUIRE(plane.model_id(" ") == "model-a");
    BOOST_REQUIRE(!plane.open(""));
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
