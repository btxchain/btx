// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// R5 (Gossip / Events) independent review, findings in audit/r5-gossip.md.
//
// Each case pins the behaviour the tree has today and, in the same case, the
// bound that must not loosen. A dedupe collision may swallow the second
// correction, but the surviving correction must still name a real original and
// the journal must not gain a phantom entry. Gossip admission may ignore the
// size of a want id, but the want count stays capped. So a case fails if the
// tree gets worse, and each names the assertion to swap in once its finding is
// fixed.
//
// The 20-peer mesh and the oversized-IHAVE case at the end are not
// characterisation: they are convergence and bound properties that must hold
// on any correct implementation.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/event_journal.h>
#include <modelnet/index_reconcile.h>
#include <modelnet/metadata_gossip.h>
#include <modelnet/model_watch.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r5_gossip_tests, BasicTestingSetup)

namespace {

modelnet::ModelEvent MakeEv(modelnet::ModelEventType t, const std::string& oid, uint64_t seq)
{
    modelnet::ModelEvent e;
    e.event_type = t;
    e.object_id = oid;
    e.model_id = oid;
    e.publisher_id = "pub-r5";
    e.record_sequence = seq;
    e.verification_state = "SIGNED_OK";
    e.source = "FEED";
    return e;
}

//! One in-process gossip participant. There is no socket: the mesh is driven
//! through the same IndexReconciler calls a wire peer would drive.
struct MeshNode {
    std::vector<std::string> ids;
};

//! Zero-padded so lexicographic order is numeric order, which is the order
//! MissingRemoteIds() walks when it truncates.
std::string WideId(int i)
{
    std::string n = std::to_string(i);
    if (n.size() < 4) n.insert(n.begin(), static_cast<std::string::size_type>(4 - n.size()), '0');
    return "obj-" + n;
}

/**
 * One pull, shaped like a real exchange: CompareSets names what we lack, our
 * own reply must satisfy our own admission rule, and only ids the peer actually
 * serves are inserted. Returns the number of ids requested.
 */
size_t PullOnce(const modelnet::IndexReconciler& rec, MeshNode& local, const MeshNode& remote,
                bool& truncated)
{
    const auto r = rec.CompareSets(local.ids, remote.ids);
    std::string err;
    BOOST_REQUIRE_MESSAGE(rec.AdmitInbound(r.outbound, err), err);
    BOOST_REQUIRE(!r.outbound.secret_bearing);
    BOOST_REQUIRE_LE(r.want_ids.size(), modelnet::RECONCILE_WANT_MAX);
    truncated = r.want_truncated;
    for (const auto& id : r.want_ids) local.ids.push_back(id);
    local.ids = modelnet::SortedUniqueIds(local.ids);
    return r.want_ids.size();
}

} // namespace

// F-3: two different originals that share object_id and record_sequence fold
// onto one *_REVERTED dedupe key, so the second correction is swallowed and
// the surviving correction's provenance names the wrong original.
BOOST_AUTO_TEST_CASE(r5_reorg_correction_collision_swallows_second)
{
    using namespace modelnet;
    ModelEventJournal j(m_path_root / "r5-reorg-collide", 32);
    std::string err;

    ObserveResult created, funded;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_CREATED, "rel-a", 4), created, err));
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::RELEASE_FUNDED, "rel-a", 4), funded, err));
    BOOST_CHECK_NE(created.event_id, funded.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 2U);

    ObserveResult rev_created, rev_funded;
    BOOST_REQUIRE(j.ObserveReorgCorrection(created.event_id, rev_created, err));
    BOOST_CHECK(!rev_created.duplicate);
    BOOST_REQUIRE(j.ObserveReorgCorrection(funded.event_id, rev_funded, err));

    // Both map to RELEASE_FUNDING_REVERTED on rel-a|4, so only one correction exists.
    BOOST_CHECK(rev_funded.duplicate);
    BOOST_CHECK_EQUAL(rev_funded.event_id, rev_created.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 3U);

    ModelEvent corr;
    BOOST_REQUIRE(j.Get(rev_funded.event_id, corr));
    BOOST_CHECK_EQUAL(corr.provenance["corrected_from"].get_str(), created.event_id);
    BOOST_CHECK_EQUAL(corr.old_state, std::string("RELEASE_CREATED"));
}

// F-4: the dedupe key carries no state or time component, so a transition
// repeated at an unchanged record_sequence is lost permanently.
BOOST_AUTO_TEST_CASE(r5_repeat_transition_same_sequence_is_swallowed)
{
    using namespace modelnet;
    ModelEventJournal j(m_path_root / "r5-flap", 32);
    std::string err;

    ObserveResult up1, down, up2;
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_RECONSTRUCTABLE, "mid-flap", 7), up1, err));
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_NO_LONGER_RECONSTRUCTABLE, "mid-flap", 7), down, err));
    BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_RECONSTRUCTABLE, "mid-flap", 7), up2, err));

    BOOST_CHECK(!up1.duplicate);
    BOOST_CHECK(!down.duplicate);
    BOOST_CHECK(up2.duplicate);
    BOOST_CHECK_EQUAL(up2.event_id, up1.event_id);
    BOOST_CHECK_EQUAL(j.Size(), 2U);
}

// F-5: once compaction evicts an event its dedupe key is gone, so re-observing
// it appends a second entry carrying the SAME event_id and re-fires the watch.
BOOST_AUTO_TEST_CASE(r5_recycled_event_after_compaction_refires_watch)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "r5-recycle";
    BindModelEventLayer(dir, 3);
    std::string err;

    ModelWatch w;
    w.kind = WatchKind::MODEL;
    w.model_id = "mid-0";
    w.action = ActionPolicy::FREE_DOWNLOAD;
    BOOST_REQUIRE(BoundModelWatchStore()->PutWatch(w, err));

    ObserveResult first;
    BOOST_REQUIRE(JournalObserve(MakeEv(ModelEventType::MODEL_PUBLISHED, "mid-0", 1), first, err));
    for (int i = 1; i <= 3; ++i) {
        ObserveResult filler;
        BOOST_REQUIRE(JournalObserve(MakeEv(ModelEventType::MODEL_PUBLISHED, "mid-" + std::to_string(i), 1), filler, err));
    }
    BOOST_CHECK_EQUAL(BoundModelEventJournal()->Size(), 3U);

    ObserveResult again;
    BOOST_REQUIRE(JournalObserve(MakeEv(ModelEventType::MODEL_PUBLISHED, "mid-0", 1), again, err));
    BOOST_CHECK(!again.duplicate);
    BOOST_CHECK_EQUAL(again.event_id, first.event_id); // same id, second entry
    BOOST_CHECK(again.local_sequence > first.local_sequence);

    const auto acts = BoundModelWatchStore()->DrainActions();
    BOOST_CHECK_EQUAL(acts.size(), 2U); // fire-once violated across compaction
    for (const auto& a : acts) {
        BOOST_CHECK_EQUAL(a.object_id, "mid-0");
        BOOST_CHECK(!a.spends);
    }
}

// F-6: compaction can drop everything below a client cursor and the replay
// page gives no indication of the loss.
BOOST_AUTO_TEST_CASE(r5_replay_past_retention_floor_is_silent)
{
    using namespace modelnet;
    ModelEventJournal j(m_path_root / "r5-gap", 3);
    std::string err;
    for (int i = 0; i < 6; ++i) {
        ObserveResult o;
        BOOST_REQUIRE(j.Observe(MakeEv(ModelEventType::MODEL_PUBLISHED, "obj-" + std::to_string(i), 1), o, err));
    }
    BOOST_CHECK_EQUAL(j.Size(), 3U);

    const auto page = j.ReplayAfter(1, 100); // client last saw local_sequence 1
    BOOST_REQUIRE_EQUAL(page.size(), 3U);
    BOOST_CHECK_EQUAL(page.front().object_id, "obj-3"); // obj-1, obj-2 lost
    BOOST_CHECK(page.front().local_sequence > 2);       // no gap signal anywhere
}

// F-7: queued actions are memory-only; nothing replays the journal into the
// watch store on load, so a restart before the drain loses them.
BOOST_AUTO_TEST_CASE(r5_queued_actions_do_not_survive_restart)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "r5-actions-restart";
    std::string err;
    {
        BindModelEventLayer(dir, 16);
        ModelWatch w;
        w.kind = WatchKind::MODEL;
        w.model_id = "mid-durable";
        w.action = ActionPolicy::FREE_DOWNLOAD;
        BOOST_REQUIRE(BoundModelWatchStore()->PutWatch(w, err));
        ObserveResult o;
        BOOST_REQUIRE(JournalObserve(MakeEv(ModelEventType::MODEL_PUBLISHED, "mid-durable", 1), o, err));
        BOOST_CHECK_EQUAL(BoundModelWatchStore()->PeekActions().size(), 1U);
    }
    BindModelEventLayer(dir, 16); // restart: watch and journal reload, queue does not
    BOOST_CHECK_EQUAL(BoundModelWatchStore()->List().size(), 1U);
    BOOST_CHECK_EQUAL(BoundModelEventJournal()->Size(), 1U);
    BOOST_CHECK_EQUAL(BoundModelWatchStore()->PeekActions().size(), 0U);
}

// F-8: admission caps the number of want ids but not their size, and never
// checks the digest field.
BOOST_AUTO_TEST_CASE(r5_gossip_admits_unbounded_want_id_size)
{
    using namespace modelnet;
    IndexReconciler rec;
    GossipMessage msg;
    msg.secret_bearing = false;
    msg.digest.catalog_digest_hex = std::string(4096, 'z'); // not hex, not 96 chars
    msg.digest.entry_count = 0xffffffffu;
    msg.want_ids.assign(RECONCILE_WANT_MAX, std::string(4096, 'a'));

    std::string err;
    BOOST_CHECK(GossipMessageAllowed(msg, err));
    BOOST_CHECK(rec.AdmitInbound(msg, err));

    msg.want_ids.push_back("one-too-many");
    BOOST_CHECK(!GossipMessageAllowed(msg, err)); // only the count is bounded
    BOOST_CHECK(err.find("want cap") != std::string::npos);
}

// F-9: holding a strict superset yields an empty want list, which is reported
// as EQUAL even though the digests differ.
BOOST_AUTO_TEST_CASE(r5_superset_reports_equal_despite_digest_mismatch)
{
    using namespace modelnet;
    const std::vector<std::string> local{"id-a", "id-b", "id-c"};
    const std::vector<std::string> remote{"id-a"};

    const GossipDigest ours = MakeCatalogDigest(local);
    const GossipDigest theirs = MakeCatalogDigest(remote);
    BOOST_CHECK_NE(ours.catalog_digest_hex, theirs.catalog_digest_hex);

    IndexReconciler rec;
    const auto r = rec.CompareSets(local, remote);
    BOOST_CHECK(r.status == ReconcileStatus::EQUAL);
    BOOST_CHECK(r.want_ids.empty());
    BOOST_CHECK(!r.want_truncated);
    BOOST_CHECK(!ReconcileDigestAuthorizesInsert());
}

// F-10: DIVIDE produces ranges that the wire type cannot carry.
BOOST_AUTO_TEST_CASE(r5_divide_ranges_are_not_carried_by_gossip_message)
{
    using namespace modelnet;
    std::vector<std::string> local;
    local.reserve(RECONCILE_WANT_MAX + 64);
    for (size_t i = 0; i < RECONCILE_WANT_MAX + 64; ++i) local.push_back("id-" + std::to_string(i));

    GossipDigest remote;
    remote.catalog_digest_hex = std::string(96, '0');
    remote.entry_count = 1;

    IndexReconciler rec;
    const auto r = rec.Compare(local, remote);
    BOOST_REQUIRE(r.status == ReconcileStatus::DIVIDE);
    BOOST_CHECK(!r.left.digest_hex.empty());
    BOOST_CHECK(!r.right.digest_hex.empty());
    // The outbound message advertises a digest only; the split is lost.
    BOOST_CHECK(r.outbound.want_ids.empty());
    BOOST_CHECK(!r.outbound.secret_bearing);
    BOOST_CHECK_EQUAL(r.outbound.digest.catalog_digest_hex, MakeCatalogDigest(local).catalog_digest_hex);
}

// Confirmed-sound pin: untrusted event text is stored verbatim and can never
// be promoted to a command, RPC, path or mandate.
BOOST_AUTO_TEST_CASE(r5_untrusted_event_text_is_inert)
{
    using namespace modelnet;
    ModelEventJournal j(m_path_root / "r5-inert", 8);
    ModelEvent ev = MakeEv(ModelEventType::MODEL_PUBLISHED, "mid-evil", 1);
    ev.untrusted_text = std::string("`id`; rm -rf /; $(reboot)\0hidden", 32);

    ObserveResult o;
    std::string err;
    BOOST_REQUIRE(j.Observe(ev, o, err));
    ModelEvent stored;
    BOOST_REQUIRE(j.Get(o.event_id, stored));
    BOOST_CHECK(stored.untrusted_text.find('\0') == std::string::npos);
    BOOST_CHECK(!EventTextMayBecomeCommand(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomeRpc(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomePath(stored.untrusted_text));
    BOOST_CHECK(!EventTextMayBecomeMandate(stored.untrusted_text));
}

// Twenty in-process peers on a ring, one hop per round, driven only by
// IndexReconciler. Anti-entropy must reach a single catalog with no peer ever
// asking for more than the want cap, and no round may converge faster than
// gossip actually travels.
BOOST_AUTO_TEST_CASE(r5_twenty_peer_mesh_converges_on_bounded_want_lists)
{
    using namespace modelnet;
    constexpr size_t kNodes = 20;
    constexpr size_t kPerNode = 3;

    IndexReconciler rec;
    std::vector<MeshNode> nodes(kNodes);
    std::vector<std::string> universe;
    for (size_t i = 0; i < kNodes; ++i) {
        for (size_t k = 0; k < kPerNode; ++k) {
            const std::string id = WideId(static_cast<int>(i * kPerNode + k));
            nodes[i].ids.push_back(id);
            universe.push_back(id);
        }
    }
    const GossipDigest all = MakeCatalogDigest(universe);
    BOOST_REQUIRE_EQUAL(all.entry_count, static_cast<uint32_t>(kNodes * kPerNode));

    // Each round pulls from a snapshot, so a node cannot ride this round's
    // arrivals at its successor. Reaching every node therefore takes kNodes - 1
    // rounds, and a mesh that "converges" sooner is inventing ids.
    size_t max_want = 0;
    for (size_t round = 1; round < kNodes; ++round) {
        const std::vector<MeshNode> before = nodes;
        for (size_t i = 0; i < kNodes; ++i) {
            bool truncated = true;
            max_want = std::max(max_want, PullOnce(rec, nodes[i], before[(i + 1) % kNodes], truncated));
            BOOST_REQUIRE(!truncated);
        }
        if (round == 1) {
            BOOST_CHECK_EQUAL(nodes[0].ids.size(), 2 * kPerNode);
        }
        if (round + 2 == kNodes) {
            for (const auto& n : nodes) BOOST_CHECK_LT(n.ids.size(), universe.size());
        }
    }

    for (size_t i = 0; i < kNodes; ++i) {
        BOOST_CHECK_EQUAL(nodes[i].ids.size(), universe.size());
        BOOST_CHECK_EQUAL(MakeCatalogDigest(nodes[i].ids).catalog_digest_hex, all.catalog_digest_hex);
        const auto settled = rec.CompareSets(nodes[i].ids, universe);
        BOOST_CHECK(settled.status == ReconcileStatus::EQUAL);
        BOOST_CHECK(settled.want_ids.empty());
    }
    BOOST_CHECK_EQUAL(max_want, kPerNode);
    BOOST_CHECK_LE(max_want, RECONCILE_WANT_MAX);
    // Convergence came from delivered ids, never from a matching fingerprint.
    BOOST_CHECK(!ReconcileDigestAuthorizesInsert());
}

// A peer that advertises far more than the want cap cannot widen one exchange,
// and the overflow is not lost: the next exchange names the rest.
BOOST_AUTO_TEST_CASE(r5_oversized_ihave_cannot_widen_one_exchange)
{
    using namespace modelnet;
    constexpr int kOffered = 300;
    static_assert(kOffered > static_cast<int>(RECONCILE_WANT_MAX));

    IndexReconciler rec;
    MeshNode seeder;
    for (int i = 0; i < kOffered; ++i) seeder.ids.push_back(WideId(i));
    MeshNode puller;

    bool truncated = false;
    BOOST_CHECK_EQUAL(PullOnce(rec, puller, seeder, truncated), RECONCILE_WANT_MAX);
    BOOST_CHECK(truncated);
    BOOST_CHECK_EQUAL(puller.ids.size(), RECONCILE_WANT_MAX);

    BOOST_CHECK_EQUAL(PullOnce(rec, puller, seeder, truncated),
                      static_cast<size_t>(kOffered) - RECONCILE_WANT_MAX);
    BOOST_CHECK(!truncated);
    BOOST_CHECK_EQUAL(puller.ids.size(), static_cast<size_t>(kOffered));
    const auto done = rec.CompareSets(puller.ids, seeder.ids);
    BOOST_CHECK(done.status == ReconcileStatus::EQUAL);
    BOOST_CHECK(done.want_ids.empty());

    // The producer bound (BoundedWantList) and the admission bound (the literal
    // 256 in metadata_gossip.cpp) must stay equal, or a reconciler emits want
    // lists that its own AdmitInbound refuses.
    GossipMessage over = MakeWantGossip(MakeCatalogDigest(seeder.ids), seeder.ids);
    std::string err;
    BOOST_CHECK_EQUAL(over.want_ids.size(), RECONCILE_WANT_MAX);
    BOOST_CHECK(rec.AdmitInbound(over, err));
    over.want_ids.push_back("one-too-many");
    BOOST_CHECK(!rec.AdmitInbound(over, err));
    BOOST_CHECK_EQUAL(err, "want cap");
}

BOOST_AUTO_TEST_SUITE_END()
