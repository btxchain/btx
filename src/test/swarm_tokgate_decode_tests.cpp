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

BOOST_FIXTURE_TEST_SUITE(swarm_tokgate_decode_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_session_is_session)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Decode("sess-missing", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!plane.Decode("", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(open_session_without_engine_is_engine_absent)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.Decode("sess-1", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.engine_name("sess-1").empty());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(!plane.launched());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(vllm_binding_is_still_engine_absent)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-1", "vllm", err));
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.Decode("sess-1", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.bytes_moved() == int64_t{0});
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(sglang_and_lmcache_are_still_engine_absent)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-s", "model-a", err));
    BOOST_REQUIRE(plane.Open("sess-l", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-s", "sglang", err));
    BOOST_REQUIRE(plane.BindEngine("sess-l", "lmcache", err));
    BOOST_REQUIRE(!plane.Decode("sess-s", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(!plane.Decode("sess-l", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.engine_name("sess-s") == "sglang");
    BOOST_REQUIRE(plane.engine_name("sess-l") == "lmcache");
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(prompt_does_not_make_decode_a_generation)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-1", "vllm", err));
    BOOST_REQUIRE(plane.Prompt("sess-1", "prompt-a", false, err));
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(!plane.Decode("sess-1", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    BOOST_REQUIRE(plane.prompt_stored("sess-1"));
    BOOST_REQUIRE(!plane.Decode("sess-1", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(!plane.measured());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
