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

BOOST_FIXTURE_TEST_SUITE(swarm_decode_private_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_session_is_session_before_private)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(!run.Prompt("sess-missing", "ab", true, err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!run.Prompt("", "ab", false, err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(run.engine_of("sess-missing").empty());
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(private_prompt_stores_nothing)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(!run.Prompt("sess-1", "ab", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!run.Prompt("sess-1", "", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(empty_public_prompt_is_prompt_and_stores_nothing)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(!run.Prompt("sess-1", "", false, err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(second_different_prompt_is_held_and_the_first_is_echoed)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(!run.Prompt("sess-1", "zz", false, err));
    BOOST_REQUIRE(err == "HELD");
    BOOST_REQUIRE(!run.Prompt("sess-1", "", false, err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.text() == "ab");
    BOOST_REQUIRE(run.tokens() == int64_t{2});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(same_prompt_again_is_replay_and_keeps_the_first)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(!run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(err == "REPLAY");
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.text() == "ab");
    BOOST_REQUIRE(run.tokens() == int64_t{2});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(private_after_a_public_prompt_keeps_the_first)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(!run.Prompt("sess-1", "zz", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.text() == "ab");
    BOOST_REQUIRE(run.tokens() == int64_t{2});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(private_prompt_on_vllm_stores_nothing)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-v", "vllm", err));
    BOOST_REQUIRE(!run.Prompt("sess-v", "ab", true, err));
    BOOST_REQUIRE(err == "PRIVATE_DATA");
    BOOST_REQUIRE(!run.Pull("sess-v", err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    BOOST_REQUIRE(run.engine_of("sess-v") == "vllm");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_SUITE_END()
