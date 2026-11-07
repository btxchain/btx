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

BOOST_FIXTURE_TEST_SUITE(swarm_decode_pull_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_session_is_session)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(!run.Pull("sess-missing", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(!run.Pull("", err));
    BOOST_REQUIRE(err == "SESSION");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(memory_without_a_prompt_is_prompt)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "PROMPT");
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(text_stays_empty_until_pull_appends)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.text().empty());
    BOOST_REQUIRE(run.tokens() == int64_t{0});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(memory_prompt_ab_pulls_two_bytes_then_done)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "ab", false, err));
    BOOST_REQUIRE(run.text().empty());

    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.text() == "a");
    BOOST_REQUIRE(run.tokens() == int64_t{1});

    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.text() == "ab");
    BOOST_REQUIRE(run.tokens() == int64_t{2});

    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == "ab");
    BOOST_REQUIRE(run.tokens() == int64_t{2});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(memory_echoes_the_caller_prompt)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "xy", false, err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.text() == "xy");
    BOOST_REQUIRE(run.tokens() == int64_t{2});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == "xy");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_SUITE_END()
