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

BOOST_FIXTURE_TEST_SUITE(swarm_decode_done_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_byte_prompt_stops_when_the_prompt_is_exhausted)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", "z", false, err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(run.text() == "z");
    BOOST_REQUIRE(run.tokens() == int64_t{1});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == "z");
    BOOST_REQUIRE(run.tokens() == int64_t{1});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(whitespace_prompt_is_echoed_as_one_byte)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", " ", false, err));
    BOOST_REQUIRE(run.Pull("sess-1", err));
    BOOST_REQUIRE(run.text() == " ");
    BOOST_REQUIRE(run.tokens() == int64_t{1});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == " ");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(eight_byte_prompt_stops_after_eight_pulls)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";
    const std::string prompt = "01234567";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", prompt, false, err));
    std::string expected;
    for (int i = 0; i < 8; ++i) {
        BOOST_REQUIRE(run.Pull("sess-1", err));
        BOOST_REQUIRE(err.empty());
        expected.push_back(prompt[i]);
        BOOST_REQUIRE(run.text() == expected);
        BOOST_REQUIRE(run.tokens() == int64_t{i + 1});
    }
    BOOST_REQUIRE(run.text() == prompt);
    BOOST_REQUIRE(run.tokens() == int64_t{8});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == prompt);
    BOOST_REQUIRE(run.tokens() == int64_t{8});
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_CASE(longer_prompt_stops_at_eight_bytes)
{
    modelnet::SwarmDecodeRun run;
    std::string err = "prior";
    const std::string prompt = "0123456789";

    BOOST_REQUIRE(run.Open("sess-1", "memory", err));
    BOOST_REQUIRE(run.Prompt("sess-1", prompt, false, err));
    std::string expected;
    for (int i = 0; i < 8; ++i) {
        BOOST_REQUIRE(run.Pull("sess-1", err));
        expected.push_back(prompt[i]);
        BOOST_REQUIRE(run.text() == expected);
        BOOST_REQUIRE(run.tokens() == int64_t{i + 1});
    }
    BOOST_REQUIRE(run.text() == "01234567");
    BOOST_REQUIRE(run.tokens() == int64_t{8});
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(!run.Pull("sess-1", err));
    BOOST_REQUIRE(err == "DONE");
    BOOST_REQUIRE(run.text() == "01234567");
    BOOST_REQUIRE(run.tokens() == int64_t{8});
    BOOST_REQUIRE(run.engine_of("sess-1") == "memory");
    ExpectQuiet(run);
}

BOOST_AUTO_TEST_SUITE_END()
