// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Independent review lane R1 (Swarm). These cases pin scheduler properties
// that the production caller in helper.cpp RetrieveFreeFromPeer depends on and
// that no existing suite asserts. They are deliberately shaped to match what
// RetrieveFreeFromPeer actually passes to the picker: empty PeerMetrics on the
// first call, PeerId with an empty service_id, netgroup set to the bare host,
// and max_per_netgroup == 8.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/piece_picker.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/transfer_session.h>
#include <modelnet/types.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <map>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_r1_swarm_tests, BasicTestingSetup)

namespace {

/** Shaped exactly like helper.cpp add_av: endpoint host:port, netgroup host, no service_id. */
modelnet::SourceAvailability LoopbackSeeder(uint16_t port, uint32_t piece_count)
{
    modelnet::SourceAvailability s;
    s.peer.endpoint = "127.0.0.1:" + std::to_string(port);
    s.peer.netgroup = "127.0.0.1";
    s.file_index = 0;
    s.piece_count = piece_count;
    return s;
}

modelnet::SourceAvailability RangeSeeder(const std::string& endpoint, const std::string& netgroup,
                                        uint32_t first, uint32_t count, uint32_t piece_count)
{
    modelnet::SourceAvailability s;
    s.peer.endpoint = endpoint;
    s.peer.netgroup = netgroup;
    s.file_index = 0;
    s.piece_count = piece_count;
    modelnet::PieceRange r;
    r.first = first;
    r.count = count;
    s.ranges.push_back(r);
    return s;
}

std::vector<uint32_t> Iota(uint32_t n)
{
    std::vector<uint32_t> v;
    v.reserve(n);
    for (uint32_t i = 0; i < n; ++i) v.push_back(i);
    return v;
}

} // namespace

// RetrieveFreeFromPeer builds PickConfig, then calls PickRarestFirst once with
// xfer.Metrics(), which is empty because ObservePeer is never called on the live
// path. An unknown peer's window is therefore exactly min_inflight_bytes, so a
// single scheduling pass can never cover more pieces than there are peers.
BOOST_AUTO_TEST_CASE(r1_unknown_peer_window_limits_one_pass_to_one_piece_per_peer)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    for (uint16_t p = 0; p < 4; ++p) srcs.push_back(LoopbackSeeder(static_cast<uint16_t>(40000 + p), 16));

    PickConfig cfg;
    cfg.max_assignments = 64;
    cfg.global_inflight_ceiling = uint64_t{256} * PIECE_SIZE;
    cfg.max_per_netgroup = 0;

    const std::map<std::string, PeerMetrics> no_metrics;
    BOOST_CHECK_EQUAL(RequestWindowBytes(PeerMetrics{}, cfg), static_cast<uint64_t>(PIECE_SIZE));

    const auto picks = PickRarestFirst(0, 16, Iota(16), srcs, no_metrics, {}, {}, cfg);
    BOOST_CHECK_EQUAL(picks.size(), srcs.size());
    std::set<std::string> endpoints;
    std::set<uint32_t> pieces;
    for (const auto& a : picks) {
        endpoints.insert(a.endpoint);
        pieces.insert(a.piece_index);
        BOOST_CHECK(!a.endgame_duplicate);
    }
    BOOST_CHECK_EQUAL(endpoints.size(), srcs.size());
    BOOST_CHECK_EQUAL(pieces.size(), srcs.size());
    // 12 of 16 missing pieces are left unscheduled by this pass.
    BOOST_CHECK_LT(pieces.size(), 16U);
}

// helper.cpp sets pcfg.max_per_netgroup = 8 and derives the netgroup from the
// bare host. Every peer in a same-host swarm therefore shares one netgroup
// bucket and the whole swarm is capped at 8 assignments per pass.
BOOST_AUTO_TEST_CASE(r1_shared_host_netgroup_caps_whole_swarm_at_eight)
{
    using namespace modelnet;
    std::vector<SourceAvailability> shared;
    std::map<std::string, PeerMetrics> metrics;
    for (uint16_t p = 0; p < 4; ++p) {
        shared.push_back(LoopbackSeeder(static_cast<uint16_t>(41000 + p), 64));
        metrics[shared.back().peer.endpoint].throughput_bps = 1e9;
    }

    PickConfig cfg;
    cfg.max_assignments = 128;
    cfg.global_inflight_ceiling = uint64_t{1024} * PIECE_SIZE;
    cfg.max_per_netgroup = 8; // production value in RetrieveFreeFromPeer

    const auto capped = PickRarestFirst(0, 64, Iota(64), shared, metrics, {}, {}, cfg);
    BOOST_CHECK_EQUAL(capped.size(), 8U);

    // The same four peers on four distinct netgroups schedule far more work,
    // so the cap and not the window is what bites on a same-host swarm.
    std::vector<SourceAvailability> spread = shared;
    for (size_t i = 0; i < spread.size(); ++i) spread[i].peer.netgroup = "ng-" + std::to_string(i);
    const auto uncapped = PickRarestFirst(0, 64, Iota(64), spread, metrics, {}, {}, cfg);
    BOOST_CHECK_GT(uncapped.size(), capped.size());
    BOOST_CHECK_GE(uncapped.size(), 16U);
}

// No peer holds the whole file: three disjoint thirds. Every piece has exactly
// one source, so the rare lane must place all of them and the swarm summary
// must report zero complete sources rather than an OK label.
BOOST_AUTO_TEST_CASE(r1_disjoint_thirds_are_fully_schedulable_and_reported_fragile)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs{
        RangeSeeder("a:1", "ng-a", 0, 3, 9),
        RangeSeeder("b:1", "ng-b", 3, 3, 9),
        RangeSeeder("c:1", "ng-c", 6, 3, 9),
    };

    PickConfig cfg;
    cfg.max_assignments = 32;
    cfg.global_inflight_ceiling = uint64_t{64} * PIECE_SIZE;

    const auto picks = PickRarestFirst(0, 9, Iota(9), srcs, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 9U);
    std::set<uint32_t> covered;
    for (const auto& a : picks) {
        covered.insert(a.piece_index);
        const std::string expect = a.piece_index < 3 ? "a:1" : (a.piece_index < 6 ? "b:1" : "c:1");
        BOOST_CHECK_EQUAL(a.endpoint, expect);
    }
    BOOST_CHECK_EQUAL(covered.size(), 9U);

    const auto snap = SummarizeSwarm(0, 9, {}, srcs, {}, cfg);
    BOOST_CHECK_EQUAL(snap.complete_sources, 0);
    BOOST_CHECK_EQUAL(snap.partial_sources, 3);
    BOOST_CHECK_EQUAL(snap.min_piece_sources, 1);
    BOOST_CHECK_EQUAL(snap.pieces_with_1_source, 9);
    BOOST_CHECK_EQUAL(std::string(ExtinctionLabel(snap)), "FRAGILE");
}

// ParseAvailabilitySources never calls CanonicalizePieceRanges, so a remote
// peer can advertise a run that extends past the end of the file, and the
// derived piece_count inherits the inflated span.
BOOST_AUTO_TEST_CASE(r1_availability_ranges_are_not_clamped_to_piece_count)
{
    using namespace modelnet;
    Digest48 artifact{};
    artifact.data[0] = 0x11;

    UniValue file(UniValue::VOBJ);
    file.pushKV("file_index", 0);
    UniValue ranges(UniValue::VARR);
    UniValue pair(UniValue::VARR);
    pair.push_back(0);
    pair.push_back(999999);
    ranges.push_back(pair);
    file.pushKV("ranges", ranges);
    UniValue files(UniValue::VARR);
    files.push_back(file);
    UniValue model(UniValue::VOBJ);
    model.pushKV("artifact_id", artifact.Hex());
    model.pushKV("files", files);
    UniValue models(UniValue::VARR);
    models.push_back(model);
    UniValue local(UniValue::VOBJ);
    local.pushKV("models", models);
    UniValue body(UniValue::VOBJ);
    body.pushKV("local", local);

    PeerId pid;
    pid.endpoint = "127.0.0.1:41100";
    pid.netgroup = "127.0.0.1";
    std::vector<SourceAvailability> out;
    std::string err;
    BOOST_REQUIRE_MESSAGE(ParseAvailabilitySources(body, pid.endpoint, pid, artifact, out, err, 1000), err);
    BOOST_REQUIRE_EQUAL(out.size(), 1U);
    BOOST_CHECK_EQUAL(out[0].piece_count, 1000000U);
    BOOST_CHECK(SourceHasPiece(out[0], 0, 999999));

    // The canonicalizer that would have rejected this run is never invoked on
    // the parse path.
    std::vector<PieceRange> copy = out[0].ranges;
    std::string cerr;
    BOOST_CHECK(!CanonicalizePieceRanges(copy, /*piece_count=*/4, cerr));
    BOOST_CHECK_EQUAL(cerr, "piece index beyond file");
}

// PeerId carries a service_id dimension, but RetrieveFreeFromPeer never fills
// it because Pq1Session exposes no peer identity. Four helper ports on one host
// are counted as four independent sources.
BOOST_AUTO_TEST_CASE(r1_missing_service_id_counts_ports_as_independent_sources)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    for (uint16_t p = 0; p < 4; ++p) srcs.push_back(LoopbackSeeder(static_cast<uint16_t>(41200 + p), 1));
    for (const auto& s : srcs) BOOST_CHECK_EQUAL(NetgroupKey(s.peer), NetgroupKey(srcs[0].peer));
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, {}), 4);

    for (auto& s : srcs) s.peer.service_id = "one-and-the-same-node";
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, {}), 1);
}

// RetrieveFreeFromPeer stores request ids in a piece_index -> request_id map,
// so an endgame duplicate overwrites the first id. The loser is then never
// committed, failed or cancelled: its credit stays reserved and it stays
// outstanding until the session is torn down. CancelAfterCommit names it but
// has no production call site.
BOOST_AUTO_TEST_CASE(r1_endgame_duplicate_loser_credit_is_stranded_until_session_cancel)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs{
        RangeSeeder("a:1", "ng-a", 0, 1, 1),
        RangeSeeder("b:1", "ng-b", 0, 1, 1),
    };
    PickConfig cfg;
    cfg.max_assignments = 8;
    cfg.global_inflight_ceiling = uint64_t{64} * PIECE_SIZE;
    BOOST_REQUIRE(EndgameActive(1, PIECE_SIZE, cfg));

    const auto picks = PickRarestFirst(0, 1, {0}, srcs, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 2U);
    BOOST_CHECK(!picks[0].endgame_duplicate);
    BOOST_CHECK(picks[1].endgame_duplicate);

    CreditBroker broker{uint64_t{8} * PIECE_SIZE};
    TransferSession sess(broker);
    std::map<uint32_t, uint64_t> piece_rid; // same shape as helper.cpp
    for (const auto& a : picks) {
        uint64_t rid = 0;
        std::string err;
        BOOST_REQUIRE_MESSAGE(sess.ReserveAndQueue(a.endpoint, 0, a.piece_index, PIECE_SIZE, rid, err), err);
        sess.NoteSent(rid);
        piece_rid[a.piece_index] = rid; // second pick overwrites the first
    }
    BOOST_REQUIRE_EQUAL(piece_rid.size(), 1U);
    BOOST_CHECK_EQUAL(broker.Reserved(), uint64_t{2} * PIECE_SIZE);

    sess.NoteCommitted(piece_rid[0], PIECE_SIZE);
    BOOST_CHECK_EQUAL(broker.Reserved(), static_cast<uint64_t>(PIECE_SIZE));
    BOOST_CHECK_EQUAL(sess.Outstanding().size(), 1U);

    const auto losers = CancelAfterCommit(sess.Outstanding(), 0, 0, picks[1].endpoint);
    BOOST_REQUIRE_EQUAL(losers.size(), 1U);
    BOOST_CHECK_EQUAL(losers[0].endpoint, picks[0].endpoint);

    sess.Cancel();
    BOOST_CHECK_EQUAL(broker.Reserved(), 0U);
    BOOST_CHECK(sess.Outstanding().empty());
}

BOOST_AUTO_TEST_SUITE_END()
