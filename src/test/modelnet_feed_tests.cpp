// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/feed.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_feed_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(econ_feed_01_dedupe_unlock)
{
    using namespace modelnet;
    FeedStore feed;
    ModelSearchRecord r;
    r.model_id.data[0] = 1;
    r.display_name = "Unlocked";
    r.canonical_name = "Unlocked";
    BOOST_CHECK(feed.NoteUnlock(r.model_id, "aa", r, 1000));
    BOOST_CHECK(feed.NoteUnlock(r.model_id, "aa", r, 1001));
    BOOST_CHECK(feed.NoteUnlock(r.model_id, "aa", r, 1002));
    FeedQuery q;
    q.mode = FeedMode::JUST_UNLOCKED;
    std::string next;
    const auto items = feed.Query(q, 2000, next);
    int unlocks = 0;
    for (const auto& ev : items) {
        if (ev.event_type == FeedEventType::MODEL_UNLOCKED) ++unlocks;
    }
    BOOST_CHECK_EQUAL(unlocks, 1);
}

BOOST_AUTO_TEST_CASE(econ_feed_05_persist)
{
    using namespace modelnet;
    const fs::path p = m_args.GetDataDirBase() / "feed-test.json";
    {
        FeedStore feed;
        feed.SetPath(p);
        ModelSearchRecord r;
        r.model_id.data[0] = 4;
        r.display_name = "PersistMe";
        r.canonical_name = "PersistMe";
        r.published_at = 50;
        BOOST_CHECK(feed.NoteSearchRecord(r, 10));
        std::string err;
        BOOST_CHECK(feed.Save(err));
    }
    FeedStore loaded;
    loaded.SetPath(p);
    std::string err;
    BOOST_CHECK(loaded.Load(20, err));
    FeedQuery q;
    std::string next;
    const auto items = loaded.Query(q, 20, next);
    BOOST_REQUIRE(!items.empty());
    BOOST_CHECK_EQUAL(items[0].rec.display_name, "PersistMe");
}

BOOST_AUTO_TEST_CASE(econ_feed_06_pagination)
{
    using namespace modelnet;
    FeedStore feed;
    for (int i = 0; i < 30; ++i) {
        ModelSearchRecord r;
        r.model_id.data[0] = static_cast<unsigned char>(i + 1);
        r.display_name = "M" + std::to_string(i);
        r.canonical_name = r.display_name;
        r.published_at = 1000 + i;
        feed.NoteSearchRecord(r, 10 + i);
    }
    FeedQuery q;
    q.limit = 10;
    std::string next;
    const auto p1 = feed.Query(q, 100, next);
    BOOST_CHECK_EQUAL(p1.size(), 10);
    BOOST_CHECK(!next.empty());
    q.cursor = next;
    const auto p2 = feed.Query(q, 100, next);
    BOOST_CHECK_EQUAL(p2.size(), 10);
    BOOST_CHECK_NE(p1.front().event_id, p2.front().event_id);
}

BOOST_AUTO_TEST_CASE(econ_feed_07_coverage_incomplete)
{
    using namespace modelnet;
    FeedCoverage cov;
    cov.complete = false;
    cov.timed_out = 2;
    FeedStore feed;
    FeedQuery q;
    const UniValue page = FeedPageJson({}, {}, q, cov, 1, "");
    BOOST_CHECK_EQUAL(page["coverage"]["complete"].get_bool(), false);
    BOOST_CHECK_EQUAL(page["coverage"]["global_complete"].get_bool(), false);
    BOOST_CHECK(page["partial"].get_bool());
}

BOOST_AUTO_TEST_CASE(econ_feed_newest_order)
{
    using namespace modelnet;
    FeedStore feed;
    ModelSearchRecord a, b;
    a.model_id.data[0] = 1;
    b.model_id.data[0] = 2;
    a.display_name = "A";
    b.display_name = "B";
    a.canonical_name = "A";
    b.canonical_name = "B";
    a.published_at = 10;
    b.published_at = 20;
    feed.NoteSearchRecord(a, 1);
    feed.NoteSearchRecord(b, 2);
    FeedQuery q;
    std::string next;
    const auto items = feed.Query(q, 3, next);
    BOOST_REQUIRE_GE(items.size(), 2);
    BOOST_CHECK_EQUAL(items[0].rec.display_name, "B");
}

BOOST_AUTO_TEST_SUITE_END()
