// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/swarm_decode_run.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmDecodeRun& run)
{
    BOOST_REQUIRE(!run.measured());
    BOOST_REQUIRE(!run.launched());
    BOOST_REQUIRE(!run.gpu());
    BOOST_REQUIRE(run.bytes_moved() == int64_t{0});
}

void ExpectIdle(const modelnet::SwarmDecodeRun& run)
{
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_decode_open_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_session_is_session_and_stores_nothing)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(!run.Open("", "memory", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(run.engine_of("").empty());
    BOOST_REQUIRE(run.engine_of("memory").empty());
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(empty_session_with_unknown_engine_is_session)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(!run.Open("", "other", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(run.engine_of("").empty());
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(unknown_engine_is_engine_and_stores_nothing)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(!run.Open("sess-1", "other", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!run.Open("sess-1", "", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!run.Open("sess-1", "Memory", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!run.Open("sess-1", "vllm ", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!run.Open("sess-1", "VLLM", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(run.engine_of("sess-1").empty());
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(known_engines_store_and_leave_text_empty)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-m", "memory", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.Open("sess-v", "vllm", err));
    BOOST_REQUIRE(run.Open("sess-s", "sglang", err));
    BOOST_REQUIRE(run.Open("sess-l", "lmcache", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.engine_of("sess-m") == "memory");
    BOOST_REQUIRE(run.engine_of("sess-v") == "vllm");
    BOOST_REQUIRE(run.engine_of("sess-s") == "sglang");
    BOOST_REQUIRE(run.engine_of("sess-l") == "lmcache");
    BOOST_REQUIRE(run.engine_of("sess-missing").empty());
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_keeps_the_first_engine)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(!run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    BOOST_REQUIRE(!run.Open("sess-1", "vllm", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    BOOST_REQUIRE(!run.Open("sess-1", "sglang", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(unknown_engine_after_open_is_engine_and_keeps_the_first)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "lmcache", err));
    BOOST_REQUIRE(!run.Open("sess-1", "other", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(run.engine_of("sess-1") == "lmcache");
    BOOST_REQUIRE(!run.Open("sess-1", "", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(run.engine_of("sess-1") == "lmcache");
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(two_sessions_keep_their_own_engines)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Open("sess-2", "vllm", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(!run.Open("sess-1", "sglang", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    BOOST_REQUIRE(run.engine_of("sess-2") == "vllm");
    ExpectIdle(run);
}

BOOST_AUTO_TEST_CASE(blank_session_is_not_trimmed)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open(" ", "memory", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.engine_of(" ") == "memory");
    BOOST_REQUIRE(run.engine_of("").empty());
    ExpectIdle(run);
}

BOOST_AUTO_TEST_SUITE_END()
