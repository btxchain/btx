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

BOOST_FIXTURE_TEST_SUITE(swarm_tokgate_prompt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_session_is_session)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Prompt("sess-missing", "prompt-a", false, err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!plane.prompt_stored("sess-missing"));
    BOOST_REQUIRE(!plane.Prompt("sess-missing", "prompt-private", true, err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!plane.prompt_stored("sess-missing"));
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(private_prompt_stores_nothing)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-private", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(!plane.Prompt("sess-1", "", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(private_prompt_does_not_occupy_the_slot)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-private", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err == "REPLAY");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_public_prompt_stores_nothing)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "", false, err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(!plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(public_prompt_is_stored_once_and_text_stays_empty)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(!plane.measured());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(same_public_prompt_is_replay)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(different_public_prompt_is_held_and_keeps_first)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-b", false, err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-b", false, err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(private_after_public_does_not_clear_the_first)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-private", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(!plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
