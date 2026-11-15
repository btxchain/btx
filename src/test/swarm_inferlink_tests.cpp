// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_inferlink/swarm_inferlink.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <string>

namespace {

std::string PrefixAtMost8(const std::string& prompt)
{
    constexpr std::size_t kCap = 8;
    return prompt.substr(0, std::min(prompt.size(), kCap));
}

void ExpectQuiet(const modelnet::SwarmInferLink& link)
{
    BOOST_CHECK(!link.measured_gpu());
    BOOST_CHECK(!link.gpu());
    BOOST_CHECK(!link.launched());
    BOOST_CHECK(!link.broadcast());
    BOOST_CHECK(link.bytes_moved() == int64_t{0});
    BOOST_CHECK_EQUAL(link.automatic_spend(), "0");
}

} // namespace

BOOST_AUTO_TEST_SUITE(swarm_inferlink_tests)

BOOST_AUTO_TEST_CASE(memory_run_text_is_the_prompt_prefix_of_at_most_eight_bytes)
{
    const std::string prompts[] = {"0123456789", "ab", "z", " "};
    for (const std::string& prompt : prompts) {
        modelnet::SwarmInferLink link;
        std::string err = "prior";
        BOOST_REQUIRE(link.Run("sess", prompt, err));
        const std::string prefix = PrefixAtMost8(prompt);
        BOOST_CHECK_EQUAL(link.text(), prefix);
        BOOST_CHECK(link.tokens() == static_cast<int64_t>(prefix.size()));
        BOOST_CHECK(prefix.size() <= 8);
        BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkDone);
        BOOST_CHECK(link.measured_local());
        BOOST_CHECK(link.ttft_ms() >= 0);
        BOOST_CHECK(link.p50_ms() >= 0);
        BOOST_CHECK(link.p95_ms() == link.p50_ms());
        BOOST_CHECK(link.ttft_ms() <= link.p50_ms());
        BOOST_CHECK_EQUAL(link.engine_of("sess"), "memory");
        ExpectQuiet(link);
    }
}

BOOST_AUTO_TEST_CASE(named_engines_leave_text_empty_and_are_engine_absent)
{
    const char* engines[] = {modelnet::kSwarmInferLinkVllm, modelnet::kSwarmInferLinkSglang, modelnet::kSwarmInferLinkLmcache};
    const std::string prompt = "0123456789";
    for (const char* engine : engines) {
        modelnet::SwarmInferLink link;
        std::string err = "prior";
        BOOST_CHECK(!link.RunNamed("sess", engine, prompt, err));
        BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkEngineAbsent);
        BOOST_CHECK(link.text().empty());
        BOOST_CHECK(link.tokens() == int64_t{0});
        BOOST_CHECK(!link.measured_local());
        BOOST_CHECK_EQUAL(link.engine_of("sess"), engine);
        ExpectQuiet(link);
    }
}

BOOST_AUTO_TEST_CASE(private_prompt_stores_nothing)
{
    modelnet::SwarmInferLink link;
    std::string err = "prior";
    BOOST_REQUIRE(link.Open("sess", "memory", err));
    BOOST_CHECK(!link.Prompt("sess", "secret-text", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkPrivateData);
    BOOST_CHECK(link.text().empty());
    BOOST_CHECK(link.tokens() == int64_t{0});
    BOOST_CHECK(!link.measured_local());
    BOOST_CHECK(!link.Pull("sess", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkPrompt);
    BOOST_CHECK(link.text().empty());
    BOOST_CHECK(link.tokens() == int64_t{0});
    ExpectQuiet(link);
}

BOOST_AUTO_TEST_CASE(empty_session_unknown_engine_and_replay)
{
    modelnet::SwarmInferLink link;
    std::string err = "prior";

    BOOST_CHECK(!link.Open("", "memory", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkSession);
    BOOST_CHECK(link.engine_of("").empty());

    BOOST_CHECK(!link.Open("sess", "other", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkEngine);
    BOOST_CHECK(link.engine_of("sess").empty());

    BOOST_REQUIRE(link.Open("sess", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!link.Open("sess", "vllm", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmInferLinkReplay);
    BOOST_CHECK_EQUAL(link.engine_of("sess"), "memory");
    BOOST_CHECK(link.text().empty());
    BOOST_CHECK(link.tokens() == int64_t{0});
    ExpectQuiet(link);
}

BOOST_AUTO_TEST_SUITE_END()
