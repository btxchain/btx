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

BOOST_FIXTURE_TEST_SUITE(swarm_tokgate_engine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_session_is_session)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.BindEngine("sess-missing", "vllm", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!plane.open("sess-missing"));
    BOOST_REQUIRE(plane.engine_name("sess-missing").empty());
    BOOST_REQUIRE(!plane.running());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_name_on_unknown_session_is_session)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.BindEngine("", "vllm", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!plane.BindEngine("sess-missing", "", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(plane.engine_name("").empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(empty_name_on_open_session_is_engine)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(plane.open("sess-1"));
    BOOST_REQUIRE(plane.engine_name("sess-1").empty());
    BOOST_REQUIRE(!plane.running());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(name_outside_catalog_is_engine_and_stores_nothing)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "cuda", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "VLLM", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "vllm ", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(plane.engine_name("sess-1").empty());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(!plane.launched());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(catalog_names_store_and_do_not_run)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-v", "model-a", err));
    BOOST_REQUIRE(plane.Open("sess-s", "model-a", err));
    BOOST_REQUIRE(plane.Open("sess-l", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-v", "vllm", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.BindEngine("sess-s", "sglang", err));
    BOOST_REQUIRE(plane.BindEngine("sess-l", "lmcache", err));
    BOOST_REQUIRE(plane.engine_name("sess-v") == "vllm");
    BOOST_REQUIRE(plane.engine_name("sess-s") == "sglang");
    BOOST_REQUIRE(plane.engine_name("sess-l") == "lmcache");
    BOOST_REQUIRE(plane.engine_name("sess-missing").empty());
    BOOST_REQUIRE(!plane.running());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.tokens() == int64_t{0});
    BOOST_REQUIRE(plane.text().empty());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(second_same_name_is_replay_and_keeps_first)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-1", "vllm", err));
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "vllm", err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.running());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_CASE(different_catalog_name_is_held_and_keeps_first)
{
    modelnet::SwarmTokenGate plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.Open("sess-1", "model-a", err));
    BOOST_REQUIRE(plane.BindEngine("sess-1", "vllm", err));
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "sglang", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "lmcache", err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.BindEngine("sess-1", "cuda", err));
    BOOST_REQUIRE(err == "ENGINE");
    BOOST_REQUIRE(plane.engine_name("sess-1") == "vllm");
    BOOST_REQUIRE(!plane.running());
    ExpectIdle(plane);
}

BOOST_AUTO_TEST_SUITE_END()
