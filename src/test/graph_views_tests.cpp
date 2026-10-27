// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/graph_views/graph_views.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::GraphViews& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(graph_views_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(four_kinds_are_counted_by_the_filter)
{
    modelnet::GraphViews eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.Add("", "record", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.contains(""));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Add("row", "rank", err));
    BOOST_CHECK_EQUAL(err, "KIND");
    BOOST_CHECK(!eng.contains("row"));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Add("row", "", err));
    BOOST_CHECK_EQUAL(err, "KIND");
    BOOST_CHECK(!eng.contains("row"));

    BOOST_CHECK(eng.Add("copy", "replication", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Add("dep", "dependency", err));
    BOOST_CHECK(eng.Add("ev", "evidence", err));
    BOOST_CHECK(eng.Add("row", "record", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(4));

    BOOST_CHECK(!eng.Add("row", "dependency", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.History("row"), "record");
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(4));

    BOOST_CHECK(eng.View("record", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.View("dependency", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.View("evidence", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.View("replication", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.View("rank", err));
    BOOST_CHECK_EQUAL(err, "KIND");
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.View("", err));
    BOOST_CHECK_EQUAL(err, "KIND");
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.contains("copy"));
    BOOST_CHECK(eng.contains("dep"));
    BOOST_CHECK(eng.contains("ev"));
    BOOST_CHECK(eng.contains("row"));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(cycle_link_is_refused_and_not_stored)
{
    modelnet::GraphViews eng;
    std::string err = "stale";

    BOOST_REQUIRE(eng.Add("a", "record", err));
    BOOST_REQUIRE(eng.Add("b", "dependency", err));
    BOOST_REQUIRE(eng.Add("c", "replication", err));

    BOOST_CHECK(!eng.Link("", "b", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.has_link("", "b"));

    BOOST_CHECK(!eng.Link("a", "missing", err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.has_link("a", "missing"));
    BOOST_CHECK(!eng.contains("missing"));

    BOOST_REQUIRE(eng.Link("a", "b", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(eng.Link("b", "c", err));
    BOOST_CHECK(eng.has_link("a", "b"));
    BOOST_CHECK(eng.has_link("b", "c"));

    BOOST_CHECK(!eng.Link("c", "a", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK(!eng.has_link("c", "a"));
    BOOST_CHECK(eng.has_link("a", "b"));
    BOOST_CHECK(eng.has_link("b", "c"));

    BOOST_CHECK(!eng.Link("b", "b", err));
    BOOST_CHECK_EQUAL(err, "CYCLE");
    BOOST_CHECK(!eng.has_link("b", "b"));

    BOOST_CHECK(eng.Dispatch(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Link("a", "b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.has_link("a", "b"));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(3));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(retract_keeps_the_first_history_text)
{
    modelnet::GraphViews eng;
    std::string err = "stale";

    BOOST_REQUIRE(eng.Add("ev", "evidence", err));
    BOOST_REQUIRE(eng.Add("row", "record", err));
    BOOST_CHECK_EQUAL(eng.History("ev"), "evidence");
    BOOST_CHECK(!eng.retracted("ev"));

    BOOST_CHECK(!eng.Retract("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.Retract("missing", err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.contains("missing"));
    BOOST_CHECK(!eng.Retract("row", err));
    BOOST_CHECK_EQUAL(err, "KIND");
    BOOST_CHECK(eng.contains("row"));
    BOOST_CHECK(!eng.retracted("row"));
    BOOST_CHECK_EQUAL(eng.History("row"), "record");

    BOOST_CHECK(eng.View("evidence", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_REQUIRE(eng.Retract("ev", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.retracted("ev"));
    BOOST_CHECK(eng.contains("ev"));
    BOOST_CHECK_EQUAL(eng.History("ev"), "evidence");
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.Retract("ev", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.History("ev"), "evidence");
    BOOST_CHECK(eng.contains("ev"));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));

    BOOST_CHECK(eng.View("record", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.View("evidence", err));
    BOOST_CHECK_EQUAL(eng.Count(), static_cast<int64_t>(1));
    BOOST_CHECK(eng.Dispatch(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
