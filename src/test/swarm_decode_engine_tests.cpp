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

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_decode_engine_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(vllm_with_a_stored_prompt_is_engine_absent)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-v", "vllm", err));
    BOOST_REQUIRE(run.engine_of("sess-v") == "vllm");
    BOOST_REQUIRE(run.Prompt("sess-v", "ab", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});

    BOOST_REQUIRE(!run.Pull("sess-v", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    BOOST_REQUIRE(!run.Pull("sess-v", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    BOOST_REQUIRE(run.engine_of("sess-v") == "vllm");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(sglang_and_lmcache_with_stored_prompts_are_engine_absent)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-s", "sglang", err));
    BOOST_REQUIRE(run.Open("sess-l", "lmcache", err));
    BOOST_REQUIRE(run.Prompt("sess-s", "sglang-prompt", false, err));
    BOOST_REQUIRE(run.Prompt("sess-l", "lmcache-prompt", false, err));
    BOOST_REQUIRE(run.text().empty());

    BOOST_REQUIRE(!run.Pull("sess-s", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(!run.Pull("sess-l", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    BOOST_REQUIRE(run.engine_of("sess-s") == "sglang");
    BOOST_REQUIRE(run.engine_of("sess-l") == "lmcache");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(production_pull_without_a_prompt_is_prompt)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-v", "vllm", err));
    BOOST_REQUIRE(!run.Pull("sess-v", err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(absent_pull_does_not_change_bytes_already_appended)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-m", "memory", err));
    BOOST_REQUIRE(run.Open("sess-v", "vllm", err));
    BOOST_REQUIRE(run.Prompt("sess-m", "ab", false, err));
    BOOST_REQUIRE(run.Prompt("sess-v", "zz", false, err));
    BOOST_REQUIRE(run.Pull("sess-m", err));
    BOOST_REQUIRE(run.text() == "a");
    BOOST_REQUIRE(run.tokens() == int64_t{1});

    BOOST_REQUIRE(!run.Pull("sess-v", err));
    BOOST_REQUIRE(err == "ENGINE_ABSENT");
    BOOST_REQUIRE(run.text() == "a");
    BOOST_REQUIRE(run.tokens() == int64_t{1});
    BOOST_REQUIRE(run.engine_of("sess-m") == "memory");
    BOOST_REQUIRE(run.engine_of("sess-v") == "vllm");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_SUITE_END()
