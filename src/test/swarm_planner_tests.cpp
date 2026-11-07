// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_planner/swarm_planner.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmPlanner& planner)
{
    BOOST_CHECK(!planner.launched());
    BOOST_CHECK(!planner.gpu());
    BOOST_CHECK(!planner.broadcast());
    BOOST_CHECK_EQUAL(planner.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(planner.bytes_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_planner_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cycle_does_not_dispatch)
{
    modelnet::SwarmPlanner planner;
    std::string err = "prior";

    BOOST_CHECK(!planner.Admit("other", "a", err));
    BOOST_CHECK_EQUAL(err, "VIEW");
    BOOST_CHECK(!planner.Admit(modelnet::kSwarmPlannerWorkView, "", err));
    BOOST_CHECK_EQUAL(err, "ID");

    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "a", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "b", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "c", err));
    BOOST_CHECK(!planner.Admit(modelnet::kSwarmPlannerWorkView, "a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerResource, "a", err));
    BOOST_CHECK(planner.admitted(modelnet::kSwarmPlannerResource, "a"));
    BOOST_CHECK(planner.admitted(modelnet::kSwarmPlannerWorkView, "a"));

    BOOST_CHECK(!planner.Depend("a", "missing", err));
    BOOST_CHECK_EQUAL(err, "WORK");

    BOOST_REQUIRE(planner.Depend("a", "b", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(planner.Depend("b", "c", err));
    BOOST_CHECK(!planner.Depend("a", "b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");

    BOOST_CHECK(!planner.Depend("c", "a", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK(!planner.Depend("b", "b", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");

    BOOST_CHECK(!planner.Dispatch("c", err));
    BOOST_CHECK_EQUAL(err, "BLOCKED");
    BOOST_CHECK(!planner.Dispatch("b", err));
    BOOST_CHECK_EQUAL(err, "BLOCKED");
    BOOST_CHECK(planner.Dispatch("a", err));
    BOOST_CHECK(err.empty());

    BOOST_REQUIRE(planner.Finish("a", err));
    BOOST_CHECK(planner.finished("a"));
    BOOST_CHECK(planner.Dispatch("b", err));
    BOOST_REQUIRE(planner.Finish("b", err));
    BOOST_CHECK(planner.Dispatch("c", err));
    BOOST_CHECK(err.empty());
    ExpectQuiet(planner);
}

BOOST_AUTO_TEST_CASE(stale_epoch_keeps_the_first_body)
{
    modelnet::SwarmPlanner planner;
    std::string err = "prior";

    BOOST_CHECK(!planner.proposed());
    BOOST_REQUIRE(planner.Propose(5, "first-body", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(planner.proposed());
    BOOST_CHECK_EQUAL(planner.epoch(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(planner.body(), "first-body");

    BOOST_CHECK(!planner.Propose(4, "other-body", err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(planner.epoch(), static_cast<int64_t>(5));
    BOOST_CHECK_EQUAL(planner.body(), "first-body");

    BOOST_CHECK(!planner.Propose(5, "replay-body", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(planner.body(), "first-body");

    BOOST_REQUIRE(planner.Propose(6, "second-body", err));
    BOOST_CHECK_EQUAL(planner.epoch(), static_cast<int64_t>(6));
    BOOST_CHECK_EQUAL(planner.body(), "second-body");
    ExpectQuiet(planner);
}

BOOST_AUTO_TEST_CASE(retracted_evidence_increases_history)
{
    modelnet::SwarmPlanner planner;
    std::string err = "prior";

    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerEvidence, "ev", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "ev", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "job", err));
    BOOST_REQUIRE(planner.Depend("ev", "job", err));

    BOOST_CHECK(!planner.Dispatch("job", err));
    BOOST_CHECK_EQUAL(err, "BLOCKED");
    BOOST_REQUIRE(planner.Finish("ev", err));
    BOOST_CHECK(planner.Dispatch("job", err));
    BOOST_CHECK(err.empty());

    const int64_t before = planner.history_count();
    BOOST_CHECK(before >= static_cast<int64_t>(1));
    BOOST_REQUIRE(planner.Retract("ev", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(planner.history_count(), before + static_cast<int64_t>(1));
    BOOST_CHECK(planner.admitted(modelnet::kSwarmPlannerEvidence, "ev"));
    BOOST_CHECK(planner.retracted("ev"));
    BOOST_CHECK(planner.admitted(modelnet::kSwarmPlannerWorkView, "ev"));

    BOOST_CHECK(!planner.Search(modelnet::kSwarmPlannerEvidence, "ev", true, err));
    BOOST_CHECK_EQUAL(err, "NOT_VISIBLE");
    BOOST_CHECK(!planner.Dispatch("job", err));
    BOOST_CHECK_EQUAL(err, "INVALID");

    const int64_t after = planner.history_count();
    BOOST_CHECK(!planner.Retract("missing", err));
    BOOST_CHECK_EQUAL(err, "ID");
    BOOST_CHECK(!planner.Retract("ev", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(planner.history_count(), after);
    ExpectQuiet(planner);
}

BOOST_AUTO_TEST_CASE(search_allowed_false_is_not_visible)
{
    modelnet::SwarmPlanner planner;
    std::string err = "prior";

    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerResource, "stored", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerWorkView, "stored", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerTopology, "stored", err));
    BOOST_REQUIRE(planner.Admit(modelnet::kSwarmPlannerEvidence, "stored", err));
    BOOST_CHECK_EQUAL(planner.visible_count(), static_cast<int64_t>(4));

    const int64_t visible = planner.visible_count();
    BOOST_CHECK(!planner.Search(modelnet::kSwarmPlannerResource, "stored", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(planner.visible_count(), visible);

    BOOST_CHECK(!planner.Search(modelnet::kSwarmPlannerResource, "missing", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(planner.visible_count(), visible);

    BOOST_CHECK(!planner.Search("other", "stored", false, err));
    BOOST_CHECK_EQUAL(err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(planner.visible_count(), visible);

    BOOST_CHECK(planner.Search(modelnet::kSwarmPlannerResource, "stored", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(planner.Search(modelnet::kSwarmPlannerWorkView, "stored", true, err));
    BOOST_CHECK(!planner.Search(modelnet::kSwarmPlannerResource, "missing", true, err));
    BOOST_CHECK_EQUAL(err, "NOT_VISIBLE");
    BOOST_CHECK_EQUAL(planner.visible_count(), visible);
    ExpectQuiet(planner);
}

BOOST_AUTO_TEST_CASE(wake_cursor_and_quiesce_stay_on_the_object)
{
    modelnet::SwarmPlanner planner;
    std::string err = "prior";

    BOOST_CHECK(!planner.quiescent());
    BOOST_CHECK(!planner.Wake("", err));
    BOOST_CHECK_EQUAL(err, "EVENT");
    BOOST_CHECK_EQUAL(planner.cursor(), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(planner.outbox_size(), static_cast<uint64_t>(0));

    BOOST_REQUIRE(planner.Wake("wake-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(planner.outbox_size(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(planner.cursor(), static_cast<uint64_t>(0));

    BOOST_CHECK(!planner.Wake("wake-1", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(planner.outbox_size(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(planner.cursor(), static_cast<uint64_t>(0));

    BOOST_CHECK_EQUAL(planner.CommitCursor(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(planner.cursor(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(planner.CommitCursor(), static_cast<uint64_t>(1));

    BOOST_REQUIRE(planner.Wake("wake-2", err));
    BOOST_CHECK_EQUAL(planner.cursor(), static_cast<uint64_t>(1));
    BOOST_CHECK_EQUAL(planner.outbox_size(), static_cast<uint64_t>(2));
    BOOST_CHECK_EQUAL(planner.CommitCursor(), static_cast<uint64_t>(2));

    BOOST_CHECK(planner.Quiesce(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(planner.quiescent());
    BOOST_CHECK(planner.Quiesce(err));
    BOOST_CHECK(planner.quiescent());

    modelnet::SwarmPlanner other;
    BOOST_CHECK(!other.quiescent());
    BOOST_CHECK_EQUAL(other.outbox_size(), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(other.cursor(), static_cast<uint64_t>(0));
    BOOST_CHECK_EQUAL(other.visible_count(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(other.history_count(), static_cast<int64_t>(0));
    BOOST_CHECK(!other.proposed());
    ExpectQuiet(planner);
    ExpectQuiet(other);
}

BOOST_AUTO_TEST_SUITE_END()
