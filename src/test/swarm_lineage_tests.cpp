// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_lineage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

static void ExpectHeads(const modelnet::SwarmLineage& line, const std::string& channel, const std::vector<std::string>& want)
{
    const std::vector<std::string> got = line.Heads(channel);
    BOOST_CHECK_EQUAL(got.size(), want.size());
    const std::size_t n = got.size() < want.size() ? got.size() : want.size();
    for (std::size_t i = 0; i < n; ++i) {
        BOOST_CHECK_EQUAL(got[i], want[i]);
    }
}

BOOST_FIXTURE_TEST_SUITE(swarm_lineage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(baseline_stores_a_head)
{
    modelnet::SwarmLineage line;
    std::string err = "prior";
    BOOST_CHECK(!line.AddBaseline("", err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_REQUIRE(line.AddBaseline("b", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(line.AddBaseline("a", err));
    BOOST_CHECK(!line.AddBaseline("b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(line.Assign("general", "a", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(line.Assign("general", "b", err));
    BOOST_REQUIRE(line.Assign("general", "b", err));
    ExpectHeads(line, "general", {"b", "a"});
    ExpectHeads(line, "coding", {});
    ExpectHeads(line, "research", {});
}

BOOST_AUTO_TEST_CASE(compatible_fork_keeps_the_parent)
{
    modelnet::SwarmLineage line;
    std::string err = "prior";
    BOOST_REQUIRE(line.AddBaseline("base", err));
    BOOST_CHECK(!line.Fork("missing", "child", true, err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK(!line.Fork("base", "", true, err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_REQUIRE(line.Fork("base", "child", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!line.Fork("base", "child", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(line.Assign("general", "child", err));
    BOOST_REQUIRE(line.Assign("general", "base", err));
    ExpectHeads(line, "general", {"base", "child"});
}

BOOST_AUTO_TEST_CASE(incompatible_fork_kept_separate)
{
    modelnet::SwarmLineage line;
    std::string err = "prior";
    BOOST_REQUIRE(line.AddBaseline("base", err));
    BOOST_REQUIRE(line.Fork("base", "side", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");
    BOOST_REQUIRE(line.Fork("base", "other", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");
    BOOST_REQUIRE(line.Assign("general", "side", err));
    BOOST_REQUIRE(line.Assign("general", "base", err));
    BOOST_REQUIRE(line.Assign("general", "other", err));
    ExpectHeads(line, "general", {"base", "side", "other"});
}

BOOST_AUTO_TEST_CASE(three_channels_stay_separate)
{
    modelnet::SwarmLineage line;
    std::string err = "prior";
    BOOST_REQUIRE(line.AddBaseline("gen", err));
    BOOST_REQUIRE(line.AddBaseline("code", err));
    BOOST_REQUIRE(line.AddBaseline("study", err));
    BOOST_CHECK(!line.Assign("ops", "gen", err));
    BOOST_CHECK_EQUAL(err, "CHANNEL");
    BOOST_CHECK(!line.Assign("general", "missing", err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_REQUIRE(line.Assign("coding", "code", err));
    BOOST_REQUIRE(line.Assign("general", "gen", err));
    BOOST_REQUIRE(line.Assign("research", "study", err));
    BOOST_REQUIRE(line.Assign("coding", "gen", err));
    BOOST_CHECK(err.empty());
    ExpectHeads(line, "general", {"gen"});
    ExpectHeads(line, "coding", {"gen", "code"});
    ExpectHeads(line, "research", {"study"});
}

BOOST_AUTO_TEST_CASE(average_changes_nothing)
{
    modelnet::SwarmLineage line;
    std::string err = "prior";
    BOOST_REQUIRE(line.AddBaseline("base", err));
    BOOST_REQUIRE(line.Fork("base", "child", true, err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(line.Fork("base", "side", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");
    BOOST_REQUIRE(line.Assign("general", "base", err));
    BOOST_REQUIRE(line.Assign("general", "child", err));
    BOOST_REQUIRE(line.Assign("general", "side", err));
    BOOST_REQUIRE(line.Assign("coding", "side", err));
    ExpectHeads(line, "general", {"base", "child", "side"});
    ExpectHeads(line, "coding", {"side"});
    BOOST_CHECK(!line.Average("base", "side", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!line.Average("child", "side", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!line.Average("", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    ExpectHeads(line, "general", {"base", "child", "side"});
    ExpectHeads(line, "coding", {"side"});
    ExpectHeads(line, "research", {});
}

BOOST_AUTO_TEST_SUITE_END()
