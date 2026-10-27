// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/research_views/research_views.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace {

bool Contains(const std::vector<std::string>& ids, const std::string& id)
{
    for (const std::string& row : ids) {
        if (row == id) return true;
    }
    return false;
}

void Idle(modelnet::ResearchViews& eng)
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
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(research_views_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_or_topic_is_field)
{
    modelnet::ResearchViews eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Put("", "topic", "note", false, false, static_cast<int64_t>(1), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.Public("topic").empty());
    BOOST_CHECK(!eng.Put("id", "", "note", true, false, static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.Public("").empty());
    BOOST_CHECK(eng.View("RECENT", "topic", err).empty());
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_row_is_hidden_from_public)
{
    modelnet::ResearchViews eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Put("pub", "shown", "seen", false, false, static_cast<int64_t>(10), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Put("hid", "shown", "kept", true, true, static_cast<int64_t>(30), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Put("tail", "shown", "also", false, false, static_cast<int64_t>(20), false, err));
    BOOST_CHECK(err.empty());

    const std::vector<std::string> pub = eng.Public("shown");
    BOOST_CHECK_EQUAL(pub.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(pub[0], "pub");
    BOOST_CHECK_EQUAL(pub[1], "tail");
    BOOST_CHECK(!Contains(pub, "hid"));

    const std::vector<std::string> recent = eng.View("RECENT", "shown", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recent.size(), static_cast<std::size_t>(3));
    BOOST_CHECK_EQUAL(recent[0], "hid");
    BOOST_CHECK_EQUAL(recent[1], "tail");
    BOOST_CHECK_EQUAL(recent[2], "pub");

    BOOST_CHECK(eng.View("REPRODUCED", "shown", err).empty());
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!Contains(eng.Public("shown"), "hid"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(negative_stays_after_positive_on_another_id)
{
    modelnet::ResearchViews eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Put("n1", "mix", "miss", true, false, static_cast<int64_t>(5), false, err));
    BOOST_CHECK(err.empty());
    const std::vector<std::string> before = eng.View("NEGLECTED", "mix", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(before.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(before[0], "mix");
    BOOST_CHECK(eng.View("CONTESTED", "mix", err).empty());

    BOOST_CHECK(eng.Put("p1", "mix", "later", false, false, static_cast<int64_t>(9), false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Put("n1", "mix", "later", false, true, static_cast<int64_t>(11), false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");

    const std::vector<std::string> pub = eng.Public("mix");
    BOOST_CHECK_EQUAL(pub.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(pub[0], "n1");
    BOOST_CHECK_EQUAL(pub[1], "p1");

    const std::vector<std::string> recent = eng.View("RECENT", "mix", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recent.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(recent[0], "p1");
    BOOST_CHECK_EQUAL(recent[1], "n1");

    const std::vector<std::string> contested = eng.View("CONTESTED", "mix", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(contested.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(contested[0], "mix");
    BOOST_CHECK(eng.View("NEGLECTED", "mix", err).empty());
    BOOST_CHECK(err.empty());

    const std::vector<std::string> leading = eng.View("LEADING", "mix", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(leading.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(leading[0], "p1");
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(five_views)
{
    modelnet::ResearchViews eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Put("early", "race", "old", false, false, static_cast<int64_t>(10), false, err));
    BOOST_CHECK(eng.Put("late_neg", "race", "miss", true, true, static_cast<int64_t>(40), false, err));
    BOOST_CHECK(eng.Put("mid", "race", "kept", false, false, static_cast<int64_t>(30), false, err));
    BOOST_CHECK(eng.Put("priv_new", "race", "local", false, true, static_cast<int64_t>(50), true, err));
    BOOST_CHECK(eng.Put("again", "race", "same", false, true, static_cast<int64_t>(15), false, err));
    BOOST_CHECK(eng.Put("q1", "quiet", "miss", true, false, static_cast<int64_t>(3), false, err));
    BOOST_CHECK(eng.Put("q2", "quiet", "miss", true, false, static_cast<int64_t>(4), false, err));
    BOOST_CHECK(eng.Put("q_priv", "quiet", "local", false, false, static_cast<int64_t>(8), true, err));
    BOOST_CHECK(err.empty());

    const std::vector<std::string> recent = eng.View("RECENT", "race", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(recent.size(), static_cast<std::size_t>(5));
    BOOST_CHECK_EQUAL(recent[0], "priv_new");
    BOOST_CHECK_EQUAL(recent[1], "late_neg");
    BOOST_CHECK_EQUAL(recent[2], "mid");
    BOOST_CHECK_EQUAL(recent[3], "again");
    BOOST_CHECK_EQUAL(recent[4], "early");

    const std::vector<std::string> reproduced = eng.View("REPRODUCED", "race", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(reproduced.size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(reproduced[0], "late_neg");
    BOOST_CHECK_EQUAL(reproduced[1], "again");
    BOOST_CHECK(!Contains(reproduced, "priv_new"));
    BOOST_CHECK(!Contains(reproduced, "early"));

    const std::vector<std::string> neglected = eng.View("NEGLECTED", "quiet", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(neglected.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(neglected[0], "quiet");
    BOOST_CHECK(eng.View("NEGLECTED", "race", err).empty());
    BOOST_CHECK(err.empty());

    const std::vector<std::string> leading = eng.View("LEADING", "race", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(leading.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(leading[0], "mid");
    BOOST_CHECK(eng.View("LEADING", "quiet", err).empty());

    const std::vector<std::string> contested = eng.View("CONTESTED", "race", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(contested.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(contested[0], "race");
    BOOST_CHECK(eng.View("CONTESTED", "quiet", err).empty());
    BOOST_CHECK(err.empty());

    BOOST_CHECK(eng.View("recent", "race", err).empty());
    BOOST_CHECK_EQUAL(err, "VIEW");
    BOOST_CHECK(eng.View("OTHER", "race", err).empty());
    BOOST_CHECK_EQUAL(err, "VIEW");
    BOOST_CHECK_EQUAL(eng.Public("race").size(), static_cast<std::size_t>(4));
    BOOST_CHECK(!Contains(eng.Public("race"), "priv_new"));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(assign_is_authority)
{
    modelnet::ResearchViews eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Put("row", "topic", "note", true, false, static_cast<int64_t>(7), false, err));
    BOOST_CHECK(err.empty());
    const std::vector<std::string> before = eng.Public("topic");
    BOOST_CHECK(!eng.Assign("author", err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK(!eng.Assign("", err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    const std::vector<std::string> after = eng.Public("topic");
    BOOST_CHECK_EQUAL(after.size(), before.size());
    BOOST_CHECK_EQUAL(after.size(), static_cast<std::size_t>(1));
    BOOST_CHECK_EQUAL(after[0], "row");
    BOOST_CHECK(eng.View("NEGLECTED", "topic", err).size() == static_cast<std::size_t>(1));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.Public("topic")[0], "row");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
