// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_descendants/descendants.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace {

bool HasId(const std::vector<std::string>& ids, const std::string& want)
{
    for (const std::string& id : ids) {
        if (id == want) return true;
    }
    return false;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_descendants_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(baseline_rejects_empty_and_duplicate)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_CHECK(!plane.AddBaseline("", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK_EQUAL(plane.size(), 0U);
    BOOST_CHECK(!plane.contains(""));

    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK_EQUAL(plane.head_of("base"), "base");
    BOOST_CHECK(plane.parent_of("base").empty());

    BOOST_CHECK(!plane.AddBaseline("base", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK_EQUAL(plane.size(), 1U);
}

BOOST_AUTO_TEST_CASE(incompatible_fork_is_its_own_head)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.AddBaseline("other", err));

    BOOST_CHECK(!plane.Fork("missing", "side", false, err));
    BOOST_CHECK_EQUAL(err, "PARENT");
    BOOST_CHECK(!plane.contains("side"));

    BOOST_CHECK(!plane.Fork("base", "", false, err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK_EQUAL(plane.size(), 2U);

    BOOST_CHECK(!plane.Fork("base", "base", false, err));
    BOOST_CHECK_EQUAL(err, "SELF");
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK(plane.parent_of("base").empty());

    BOOST_REQUIRE(plane.Fork("base", "side", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");
    BOOST_CHECK(plane.is_head("side"));
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK_EQUAL(plane.head_of("side"), "side");
    BOOST_CHECK_EQUAL(plane.head_of("base"), "base");
    BOOST_CHECK_EQUAL(plane.parent_of("side"), "base");
    BOOST_CHECK(HasId(plane.on_head("base"), "base"));
    BOOST_CHECK(!HasId(plane.on_head("base"), "side"));
    BOOST_CHECK(HasId(plane.on_head("side"), "side"));

    BOOST_CHECK(!plane.Fork("other", "side", true, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(plane.parent_of("side"), "base");
    BOOST_CHECK(plane.is_head("side"));
    BOOST_CHECK(plane.is_head("base"));
}

BOOST_AUTO_TEST_CASE(compatible_child_stays_on_the_parent_head)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.Fork("base", "child", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!plane.is_head("child"));
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK_EQUAL(plane.head_of("child"), "base");
    BOOST_CHECK_EQUAL(plane.parent_of("child"), "base");
    BOOST_CHECK(HasId(plane.on_head("base"), "base"));
    BOOST_CHECK(HasId(plane.on_head("base"), "child"));

    BOOST_CHECK(!plane.Fork("base", "child", false, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!plane.is_head("child"));
    BOOST_CHECK_EQUAL(plane.parent_of("child"), "base");
    BOOST_CHECK_EQUAL(plane.head_of("child"), "base");
}

BOOST_AUTO_TEST_CASE(average_is_refused)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.Fork("base", "child", true, err));
    BOOST_REQUIRE(plane.Fork("base", "side", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");

    const std::vector<std::string> heads_before = plane.heads();
    const std::string child_head = plane.head_of("child");
    const std::string side_head = plane.head_of("side");
    const std::string side_parent = plane.parent_of("side");

    BOOST_CHECK(!plane.Average("child", "side", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!plane.Average(err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK(!plane.Average("", "", err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");

    BOOST_CHECK_EQUAL(plane.heads().size(), heads_before.size());
    for (std::size_t i = 0; i < heads_before.size(); ++i) {
        BOOST_CHECK_EQUAL(plane.heads()[i], heads_before[i]);
    }
    BOOST_CHECK_EQUAL(plane.head_of("child"), child_head);
    BOOST_CHECK_EQUAL(plane.head_of("side"), side_head);
    BOOST_CHECK_EQUAL(plane.parent_of("side"), side_parent);
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK(plane.is_head("side"));
    BOOST_CHECK(!plane.is_head("child"));
}

BOOST_AUTO_TEST_CASE(three_niches_stay)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("gen", err));
    BOOST_REQUIRE(plane.AddBaseline("code", err));
    BOOST_REQUIRE(plane.AddBaseline("study", err));

    BOOST_CHECK(!plane.Assign("gen", "ops", err));
    BOOST_CHECK_EQUAL(err, "NICHE");
    BOOST_CHECK(plane.channels("gen").empty());
    BOOST_CHECK(plane.heads("ops").empty());

    BOOST_CHECK(!plane.Assign("missing", "general", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");

    BOOST_REQUIRE(plane.Assign("gen", "general", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(plane.Assign("code", "coding", err));
    BOOST_REQUIRE(plane.Assign("study", "research", err));
    BOOST_REQUIRE(plane.Assign("gen", "coding", err));
    BOOST_REQUIRE(plane.Assign("gen", "research", err));
    BOOST_REQUIRE(plane.Assign("gen", "general", err));

    const std::vector<std::string> gen_channels = plane.channels("gen");
    BOOST_REQUIRE_EQUAL(gen_channels.size(), 3U);
    BOOST_CHECK_EQUAL(gen_channels[0], "general");
    BOOST_CHECK_EQUAL(gen_channels[1], "coding");
    BOOST_CHECK_EQUAL(gen_channels[2], "research");
    BOOST_CHECK_EQUAL(plane.channels("code").size(), 1U);
    BOOST_CHECK_EQUAL(plane.channels("code")[0], "coding");
    BOOST_CHECK_EQUAL(plane.channels("study").size(), 1U);
    BOOST_CHECK_EQUAL(plane.channels("study")[0], "research");

    const std::vector<std::string> general = plane.heads("general");
    BOOST_REQUIRE_EQUAL(general.size(), 1U);
    BOOST_CHECK_EQUAL(general[0], "gen");
    const std::vector<std::string> coding = plane.heads("coding");
    BOOST_REQUIRE_EQUAL(coding.size(), 2U);
    BOOST_CHECK_EQUAL(coding[0], "gen");
    BOOST_CHECK_EQUAL(coding[1], "code");
    const std::vector<std::string> research = plane.heads("research");
    BOOST_REQUIRE_EQUAL(research.size(), 2U);
    BOOST_CHECK_EQUAL(research[0], "gen");
    BOOST_CHECK_EQUAL(research[1], "study");
}

BOOST_AUTO_TEST_CASE(author_self_score_is_refused)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.Fork("base", "side", false, err));
    BOOST_CHECK_EQUAL(err, "FORK");

    BOOST_CHECK(!plane.Measure("side", "side", true, 10, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(plane.scores("side").empty());
    BOOST_CHECK(!plane.accepted("side"));
    BOOST_CHECK(plane.is_head("side"));
    BOOST_CHECK_EQUAL(plane.head_of("side"), "side");
    BOOST_CHECK(plane.is_head("base"));

    BOOST_CHECK(!plane.Measure("side", "", true, 10, err));
    BOOST_CHECK_EQUAL(err, "NOT_SCORED");
    BOOST_CHECK(plane.scores("side").empty());
}

BOOST_AUTO_TEST_CASE(held_score_is_not_stored)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("side", err));
    BOOST_CHECK(!plane.Measure("side", "alice", false, 10, err));
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(plane.scores("side").empty());
    BOOST_CHECK(!plane.accepted("side"));
    BOOST_CHECK(plane.is_head("side"));
}

BOOST_AUTO_TEST_CASE(two_authors_within_spread_are_accepted)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("side", err));
    BOOST_REQUIRE(plane.Measure("side", "alice", true, 0, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!plane.accepted("side"));

    BOOST_REQUIRE(plane.Measure("side", "bob", true, 10000, err));
    BOOST_CHECK(plane.accepted("side"));
    BOOST_CHECK(!plane.graduated());

    const std::vector<modelnet::SwarmDescendantScore> rows = plane.scores("side");
    BOOST_REQUIRE_EQUAL(rows.size(), 2U);
    BOOST_CHECK_EQUAL(rows[0].author, "alice");
    BOOST_CHECK_EQUAL(rows[0].score, 0);
    BOOST_CHECK_EQUAL(rows[1].author, "bob");
    BOOST_CHECK_EQUAL(rows[1].score, 10000);

    BOOST_CHECK(!plane.Measure("side", "alice", true, 50, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    const std::vector<modelnet::SwarmDescendantScore> kept = plane.scores("side");
    BOOST_REQUIRE_EQUAL(kept.size(), 2U);
    BOOST_CHECK_EQUAL(kept[0].score, 0);
    BOOST_CHECK(plane.is_head("side"));
}

BOOST_AUTO_TEST_CASE(wide_spread_is_not_accepted)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("wide", err));
    BOOST_REQUIRE(plane.Measure("wide", "alice", true, 0, err));
    BOOST_REQUIRE(plane.Measure("wide", "bob", true, 10001, err));
    BOOST_CHECK(!plane.accepted("wide"));
    BOOST_REQUIRE_EQUAL(plane.scores("wide").size(), 2U);
    BOOST_CHECK_EQUAL(plane.scores("wide")[0].score, 0);
    BOOST_CHECK_EQUAL(plane.scores("wide")[1].score, 10001);
}

BOOST_AUTO_TEST_CASE(score_does_not_replace_a_head)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.Fork("base", "child", true, err));
    BOOST_REQUIRE(plane.Measure("child", "alice", true, 4, err));
    BOOST_REQUIRE(plane.Measure("child", "bob", true, 9, err));
    BOOST_CHECK(plane.accepted("child"));
    BOOST_CHECK(!plane.is_head("child"));
    BOOST_CHECK(plane.is_head("base"));
    BOOST_CHECK_EQUAL(plane.head_of("child"), "base");
    BOOST_CHECK_EQUAL(plane.parent_of("child"), "base");
    BOOST_CHECK(!plane.graduated());
    BOOST_CHECK(!HasId(plane.heads(), "child"));
}

BOOST_AUTO_TEST_CASE(bytes_gpu_and_graduation_stay_idle)
{
    modelnet::SwarmDescendants plane;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(plane.bytes_moved(), uint64_t{0});
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.graduated());
    BOOST_CHECK(!plane.promotes_realm());
    BOOST_CHECK(!plane.mines());

    BOOST_REQUIRE(plane.AddBaseline("base", err));
    BOOST_REQUIRE(plane.Fork("base", "side", false, err));
    BOOST_REQUIRE(plane.Assign("side", "research", err));
    BOOST_REQUIRE(plane.Measure("side", "alice", true, 1, err));
    BOOST_REQUIRE(plane.Measure("side", "bob", true, 2, err));
    BOOST_CHECK(!plane.Average("base", "side", err));

    BOOST_CHECK_EQUAL(plane.bytes_moved(), uint64_t{0});
    BOOST_CHECK(!plane.gpu());
    BOOST_CHECK(!plane.graduated());
    BOOST_CHECK(!plane.promotes_realm());
    BOOST_CHECK(!plane.mines());
    BOOST_CHECK(plane.accepted("side"));
}

BOOST_AUTO_TEST_CASE(integer_pairs_stay_frozen)
{
    modelnet::SwarmDescendants plane;
    BOOST_REQUIRE_EQUAL(modelnet::IntegerDataset().size(), 8U);
    BOOST_CHECK_EQUAL(plane.integer_pairs(), modelnet::IntegerDataset().size());
    BOOST_CHECK_EQUAL(std::string(plane.integer_profile()), std::string(modelnet::INTEGER_PROFILE));
    BOOST_CHECK(!plane.extends_dataset());
    BOOST_CHECK(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
