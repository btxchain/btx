// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/event_journal.h>
#include <modelnet/feed.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <csignal>
#include <fstream>
#include <iterator>
#include <string>

#if !defined(_WIN32)
#include <sys/resource.h>
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_event_tests, BasicTestingSetup)

namespace {

modelnet::ModelEvent MakeEv(modelnet::ModelEventType t, const std::string& oid, uint64_t seq = 1)
{
    modelnet::ModelEvent e;
    e.event_type = t;
    e.object_id = oid;
    e.model_id = oid;
    e.publisher_id = "aa";
    e.record_sequence = seq;
    e.verification_state = "SIGNED_OK";
    e.source = "FEED";
    return e;
}

} // namespace

BOOST_AUTO_TEST_CASE(event_restart_persists_sequence)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-restart";
    fs::create_directories(dir);
    std::string event_id;
    uint64_t seq = 0;
    {
        ModelEventJournal j(dir, 32);
        ObserveResult o;
        std::string err;
        BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "01"), o, err));
        BOOST_CHECK(!o.duplicate);
        event_id = o.event_id;
        seq = o.local_sequence;
        BOOST_CHECK_EQUAL(j.Size(), 1U);
        BOOST_CHECK_EQUAL(j.Cursor(), seq);
        BOOST_CHECK(fs::exists(dir / "events" / "journal.jsonl"));
        BOOST_CHECK(fs::exists(dir / "events" / "seq"));
    }
    {
        ModelEventJournal j(dir, 32);
        BOOST_CHECK_EQUAL(j.Size(), 1U);
        BOOST_CHECK_EQUAL(j.Cursor(), seq);
        ModelEvent got;
        BOOST_REQUIRE(j.Get(event_id, got));
        BOOST_CHECK_EQUAL(got.event_id, event_id);
        BOOST_CHECK_EQUAL(ModelEventTypeName(got.event_type), std::string("MODEL_PUBLISHED"));
        const auto replay = j.ReplayAfter(0);
        BOOST_REQUIRE_EQUAL(replay.size(), 1U);
        BOOST_CHECK_EQUAL(replay[0].local_sequence, seq);
        ObserveResult o;
        std::string err;
        BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_METADATA_UPDATED, "01", 2), o, err));
        BOOST_CHECK_EQUAL(o.local_sequence, seq + 1);
    }
}

BOOST_AUTO_TEST_CASE(event_failed_append_is_not_kept)
{
    // An event whose journal line could not be written must not be served, must
    // not take a sequence number, and must not make the retried observation a
    // duplicate. Otherwise the retry is never written, the event is gone after a
    // restart, and the next start hands its sequence to another event, which a
    // reader that already holds that cursor then skips.
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-append-fail";
    fs::create_directories(dir);
    ModelEventJournal j(dir, 32);
    const fs::path journal = dir / "events" / "journal.jsonl";
    // A directory where the journal file belongs makes the append fail.
    fs::create_directories(journal);
    ObserveResult o;
    std::string err;
    BOOST_CHECK(!j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "01"), o, err));
    BOOST_CHECK_EQUAL(err, "journal append");
    BOOST_CHECK_EQUAL(j.Size(), 0U);
    BOOST_CHECK_EQUAL(j.Cursor(), 0U);
    BOOST_CHECK(j.ReplayAfter(0).empty());

    fs::remove(journal);
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "01"), o, err));
    BOOST_CHECK(!o.duplicate);
    BOOST_CHECK_EQUAL(o.local_sequence, 1U);
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "02"), o, err));
    BOOST_CHECK_EQUAL(o.local_sequence, 2U);

    ModelEventJournal reloaded(dir, 32);
    BOOST_CHECK_EQUAL(reloaded.Size(), 2U);
    BOOST_CHECK_EQUAL(reloaded.Cursor(), 2U);
    const auto replay = reloaded.ReplayAfter(0);
    BOOST_REQUIRE_EQUAL(replay.size(), 2U);
    BOOST_CHECK_EQUAL(replay[0].object_id, "01");
    BOOST_CHECK_EQUAL(replay[1].object_id, "02");
}

BOOST_AUTO_TEST_CASE(event_append_after_torn_line_is_kept)
{
    // A crash during a write can leave the journal ending in half a line. The
    // next event must start on its own line, or both are lost on the next load.
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-torn-line";
    fs::create_directories(dir / "events");
    {
        std::ofstream out(dir / "events" / "journal.jsonl", std::ios::binary);
        out << "{\"event_id\":\"cut-short";
    }
    {
        ModelEventJournal j(dir, 32);
        ObserveResult o;
        std::string err;
        BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "01"), o, err));
    }
    ModelEventJournal reloaded(dir, 32);
    BOOST_CHECK_EQUAL(reloaded.Size(), 1U);
    BOOST_CHECK_EQUAL(reloaded.Cursor(), 1U);
}

#if !defined(_WIN32)
BOOST_AUTO_TEST_CASE(event_write_failure_leaves_no_torn_line)
{
    // A full disk can fail the write of a line part way. The journal must be
    // cut back, so that the retried observation is one whole line on disk.
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-write-fail";
    fs::create_directories(dir);
    ModelEventJournal j(dir, 32);
    ObserveResult o;
    std::string err;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "01"), o, err));
    const fs::path journal = dir / "events" / "journal.jsonl";
    const auto read = [&] {
        std::ifstream in(journal, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(in), {});
    };
    const std::string committed = read();
    struct rlimit saved{};
    BOOST_REQUIRE_EQUAL(getrlimit(RLIMIT_FSIZE, &saved), 0);
    const auto handler = std::signal(SIGXFSZ, SIG_IGN);
    BOOST_REQUIRE(handler != SIG_ERR);
    struct rlimit limited = saved;
    limited.rlim_cur = committed.size() + 10;
    if (setrlimit(RLIMIT_FSIZE, &limited) != 0) {
        std::signal(SIGXFSZ, handler);
        BOOST_FAIL("setrlimit failed");
    }
    const bool ok = j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "02"), o, err);
    if (setrlimit(RLIMIT_FSIZE, &saved) != 0) std::terminate();
    std::signal(SIGXFSZ, handler);
    BOOST_CHECK(!ok);
    BOOST_CHECK_EQUAL(read(), committed);
    BOOST_CHECK_EQUAL(j.Size(), 1U);

    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "02"), o, err));
    BOOST_CHECK(!o.duplicate);
    ModelEventJournal reloaded(dir, 32);
    BOOST_CHECK_EQUAL(reloaded.Size(), 2U);
    BOOST_CHECK_EQUAL(reloaded.Cursor(), 2U);
}
#endif

BOOST_AUTO_TEST_CASE(event_dedupe_same_object_sequence_transition)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-dedupe";
    ModelEventJournal j(dir, 32);
    ObserveResult a, b;
    std::string err;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_FUNDED, "rel1", 7), a, err));
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_FUNDED, "rel1", 7), b, err));
    BOOST_CHECK(!a.duplicate);
    BOOST_CHECK(b.duplicate);
    BOOST_CHECK_EQUAL(a.event_id, b.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 1U);
    ObserveResult c;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_FUNDING_CHANGED, "rel1", 7), c, err));
    BOOST_CHECK(!c.duplicate);
    BOOST_CHECK_NE(c.event_id, a.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 2U);
}

BOOST_AUTO_TEST_CASE(event_reorg_correction_keeps_original)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-reorg";
    ModelEventJournal j(dir, 32);
    ObserveResult funded, rev;
    std::string err;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_FUNDED, "rel2", 3), funded, err));
    BOOST_REQUIRE(j.ObserveReorgCorrection(funded.event_id, rev, err));
    BOOST_CHECK(!rev.duplicate);
    BOOST_CHECK_NE(rev.event_id, funded.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 2U);
    ModelEvent orig, corr;
    BOOST_REQUIRE(j.Get(funded.event_id, orig));
    BOOST_REQUIRE(j.Get(rev.event_id, corr));
    BOOST_CHECK_EQUAL(ModelEventTypeName(orig.event_type), std::string("RELEASE_FUNDED"));
    BOOST_CHECK_EQUAL(ModelEventTypeName(corr.event_type), std::string("RELEASE_FUNDING_REVERTED"));
    BOOST_CHECK_EQUAL(corr.old_state, std::string("RELEASE_FUNDED"));
    BOOST_CHECK_EQUAL(corr.object_id, orig.object_id);
    BOOST_CHECK_EQUAL(corr.record_sequence, orig.record_sequence);
    ObserveResult rev2;
    BOOST_REQUIRE(j.ObserveReorgCorrection(funded.event_id, rev2, err));
    BOOST_CHECK(rev2.duplicate);
    BOOST_CHECK_EQUAL(rev2.event_id, rev.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 2U);
}

BOOST_AUTO_TEST_CASE(event_compact_keeps_last_n)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-cap";
    ModelEventJournal j(dir, 3);
    std::string err;
    for (int i = 0; i < 5; ++i) {
        ObserveResult o;
        BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "m" + std::to_string(i), 1), o, err));
    }
    BOOST_CHECK_EQUAL(j.Size(), 3U);
    const auto page = j.ReplayAfter(0, 100);
    BOOST_REQUIRE_EQUAL(page.size(), 3U);
    BOOST_CHECK_EQUAL(page[0].object_id, "m2");
    BOOST_CHECK_EQUAL(page[2].object_id, "m4");
}

BOOST_AUTO_TEST_CASE(event_malicious_description_is_stored_not_executed)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "event-malicious";
    fs::create_directories(dir);
    const fs::path marker = dir / "must-survive";
    {
        std::ofstream out(marker);
        out << "ok\n";
    }
    ModelEventJournal j(dir, 16);
    ModelEvent ev = MakeEv(ModelEventType::MODEL_PUBLISHED, "evil");
    ev.untrusted_text = "; rm -rf " + fs::PathToString(dir) + "; $(reboot) `id`; watchmodelpublisher; /wallet/keys";
    ObserveResult o;
    std::string err;
    BOOST_REQUIRE(j.Observe(ev, o, err));
    ModelEvent stored;
    BOOST_REQUIRE(j.Get(o.event_id, stored));
    BOOST_CHECK(stored.untrusted_text.find("rm -rf") != std::string::npos);
    BOOST_CHECK(!EventTextMayBecomeCommand(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomeRpc(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomePath(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomeMandate(stored.untrusted_text));
    BOOST_CHECK(fs::exists(marker));
    BOOST_CHECK(fs::exists(dir / "events" / "journal.jsonl"));
}

BOOST_AUTO_TEST_CASE(event_from_feed_normalizes_types)
{
    using namespace modelnet;
    FeedEvent fe;
    fe.event_type = FeedEventType::MODEL_UNLOCKED;
    fe.model_id.data[0] = 9;
    fe.release_id = "rel";
    fe.signed_record = true;
    fe.rec.short_description = "hello";
    ModelEvent ev;
    BOOST_REQUIRE(ModelEventFromFeed(fe, ev));
    BOOST_CHECK_EQUAL(ModelEventTypeName(ev.event_type), std::string("RELEASE_UNLOCKED"));
    BOOST_CHECK_EQUAL(ev.source, "FEED");
    BOOST_CHECK_EQUAL(ev.untrusted_text, "hello");
}

BOOST_AUTO_TEST_CASE(event_from_bounty_event)
{
    using namespace modelnet;
    UniValue e(UniValue::VOBJ);
    e.pushKV("kind", "publish");
    e.pushKV("bounty_id", std::string(96, 'b'));
    e.pushKV("seq", 1);
    e.pushKV("event_id", "e1");
    e.pushKV("authority", "local_signed_or_chain");
    ModelEvent ev;
    BOOST_REQUIRE(ModelEventFromBountyEvent(e, ev));
    BOOST_CHECK_EQUAL(ev.object_kind, "BOUNTY");
    BOOST_CHECK_EQUAL(ev.source, "BOUNTY");
    ObserveResult o;
    std::string err;
    const fs::path dir = m_path_root / "event-bounty";
    BindModelEventJournal(dir, 16);
    BOOST_REQUIRE(JournalObserveBounty(e, o, err));
    BOOST_CHECK(!o.event_id.empty());
}

BOOST_AUTO_TEST_SUITE_END()
