// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/model_nat.h>
#include <modelnet/piece_picker.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/policy.h>
#include <modelnet/provider_exchange.h>
#include <modelnet/store.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_swarm_tests, BasicTestingSetup)

namespace {

modelnet::SourceAvailability MakeSrc(const std::string& ep, uint32_t file, uint32_t first, uint32_t count,
                                     const std::string& service = {}, const std::string& netgroup = {})
{
    modelnet::SourceAvailability s;
    s.peer.endpoint = ep;
    s.peer.service_id = service;
    s.peer.netgroup = netgroup;
    s.file_index = file;
    modelnet::PieceRange r;
    r.first = first;
    r.count = count;
    s.ranges.push_back(r);
    return s;
}

std::vector<unsigned char> TinySafeTensors(unsigned char tag)
{
    const std::string json = "{\"__metadata__\":{\"t\":\"" + std::to_string(static_cast<int>(tag)) + "\"}}";
    std::vector<unsigned char> st(8 + json.size(), 0);
    WriteLE64(st.data(), json.size());
    std::memcpy(st.data() + 8, json.data(), json.size());
    return st;
}

} // namespace

BOOST_AUTO_TEST_CASE(swarm_rf_01_rare_before_common)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("a", 0, 0, 11));
    srcs.push_back(MakeSrc("b", 0, 1, 10));
    srcs.push_back(MakeSrc("c", 0, 1, 10));
    srcs.push_back(MakeSrc("d", 0, 1, 10));
    srcs.push_back(MakeSrc("e", 0, 1, 10));
    srcs.push_back(MakeSrc("f", 0, 1, 10));
    srcs.push_back(MakeSrc("g", 0, 1, 10));
    srcs.push_back(MakeSrc("h", 0, 1, 10));
    srcs.push_back(MakeSrc("i", 0, 1, 10));
    srcs.push_back(MakeSrc("j", 0, 1, 10));
    srcs.push_back(MakeSrc("k", 0, 1, 10));
    std::vector<uint32_t> missing;
    for (uint32_t i = 0; i < 11; ++i) missing.push_back(i);
    PickConfig cfg;
    cfg.rng_seed = 7;
    cfg.max_assignments = 1;
    const auto picks = PickRarestFirst(0, 11, missing, srcs, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1);
    BOOST_CHECK_EQUAL(picks[0].piece_index, 0U);
}

BOOST_AUTO_TEST_CASE(swarm_rf_02_ties_randomized)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("a", 0, 0, 8));
    srcs.push_back(MakeSrc("b", 0, 0, 8));
    std::vector<uint32_t> missing;
    for (uint32_t i = 0; i < 8; ++i) missing.push_back(i);
    std::set<uint32_t> firsts;
    for (uint32_t seed = 1; seed < 40; ++seed) {
        PickConfig cfg;
        cfg.rng_seed = seed;
        cfg.max_assignments = 1;
        const auto picks = PickRarestFirst(0, 8, missing, srcs, {}, {}, {}, cfg);
        BOOST_REQUIRE_EQUAL(picks.size(), 1);
        firsts.insert(picks[0].piece_index);
    }
    BOOST_CHECK_GE(firsts.size(), 2);
}

BOOST_AUTO_TEST_CASE(swarm_rf_03_stale_source_changes_rarity)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    auto a = MakeSrc("a", 0, 0, 1);
    a.last_update_ms = 1;
    auto b = MakeSrc("b", 0, 0, 1);
    b.last_update_ms = 1;
    srcs.push_back(a);
    srcs.push_back(b);
    PickConfig cfg;
    cfg.now_ms = 1000;
    cfg.stale_after_ms = 50;
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, cfg), 0);
    cfg.stale_after_ms = 10000;
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, cfg), 2);
}

BOOST_AUTO_TEST_CASE(swarm_rf_04_duplicate_identity_not_double_counted)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("a:1", 0, 0, 1, "aabb"));
    srcs.push_back(MakeSrc("a:2", 0, 0, 1, "aabb"));
    BOOST_CHECK_EQUAL(PieceRarity(0, 0, srcs, {}, {}), 1);
}

BOOST_AUTO_TEST_CASE(swarm_rf_05_sole_slow_source_retained)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("slow", 0, 0, 1));
    srcs.push_back(MakeSrc("fast", 0, 1, 10));
    std::map<std::string, PeerMetrics> metrics;
    metrics["slow"].state = PeerXferState::SNUBBED;
    metrics["slow"].throughput_bps = 50 * 1024;
    metrics["fast"].throughput_bps = 10 * 1024 * 1024;
    std::vector<uint32_t> missing = {0};
    PickConfig cfg;
    cfg.max_assignments = 1;
    const auto picks = PickRarestFirst(0, 11, missing, srcs, metrics, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1);
    BOOST_CHECK_EQUAL(picks[0].endpoint, "slow");
    BOOST_CHECK_EQUAL(picks[0].piece_index, 0U);
}

BOOST_AUTO_TEST_CASE(swarm_rf_06_bootstrap_then_rarest)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("a", 0, 0, 4));
    srcs.push_back(MakeSrc("b", 0, 1, 3));
    std::vector<uint32_t> missing = {0, 1, 2, 3};
    PickConfig boot;
    boot.bootstrap_remaining = 4;
    boot.rng_seed = 3;
    boot.max_assignments = 4;
    const auto b = PickRarestFirst(0, 4, missing, srcs, {}, {}, {}, boot);
    BOOST_CHECK(!b.empty());
    PickConfig rf;
    rf.bootstrap_remaining = 0;
    rf.max_assignments = 1;
    const auto r = PickRarestFirst(0, 4, missing, srcs, {}, {}, {}, rf);
    BOOST_REQUIRE(!r.empty());
    BOOST_CHECK_EQUAL(r[0].piece_index, 0U);
}

BOOST_AUTO_TEST_CASE(swarm_eg_01_07_endgame)
{
    using namespace modelnet;
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("a", 0, 0, 2));
    srcs.push_back(MakeSrc("b", 0, 0, 2));
    std::vector<uint32_t> missing = {1};
    PickConfig cfg;
    cfg.endgame_piece_threshold = 4;
    cfg.max_duplicate_sources = 2;
    cfg.max_assignments = 8;
    BOOST_CHECK(EndgameActive(1, PIECE_SIZE, cfg));
    const auto picks = PickRarestFirst(0, 2, missing, srcs, {}, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 2);
    std::set<std::string> eps;
    for (const auto& p : picks) {
        BOOST_CHECK_EQUAL(p.piece_index, 1U);
        eps.insert(p.endpoint);
    }
    BOOST_CHECK_EQUAL(eps.size(), 2);
    BOOST_CHECK(picks[1].endgame_duplicate);
    OutstandingSet out;
    out.insert({"a", 0, 1});
    out.insert({"b", 0, 1});
    const auto cancel = CancelAfterCommit(out, 0, 1, "a");
    BOOST_REQUIRE_EQUAL(cancel.size(), 1);
    BOOST_CHECK_EQUAL(cancel[0].endpoint, "b");
}

BOOST_AUTO_TEST_CASE(swarm_eg_06_no_double_reciprocity)
{
    modelnet::ReciprocityLedger led;
    BOOST_CHECK(led.Received("a", "art", 0, 1, 100, 1, true, true, false, 2));
    BOOST_CHECK(!led.Received("b", "art", 0, 1, 100, 2, true, true, false, 2));
}

BOOST_AUTO_TEST_CASE(swarm_eg_07_automatic_spend_zero)
{
    BOOST_CHECK_EQUAL(modelnet::CapabilitiesObject()["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(swarm_eg_08_corrupt_then_valid)
{
    using namespace modelnet;
    std::map<std::string, PeerMetrics> metrics;
    metrics["bad"].invalid_piece_count = 2;
    BOOST_CHECK(ClassifyPeer(metrics["bad"]) == PeerXferState::FAILED);
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("bad", 0, 0, 1));
    srcs.push_back(MakeSrc("good", 0, 0, 1));
    std::vector<uint32_t> missing = {0};
    PickConfig cfg;
    cfg.max_assignments = 1;
    const auto picks = PickRarestFirst(0, 1, missing, srcs, metrics, {}, {}, cfg);
    BOOST_REQUIRE_EQUAL(picks.size(), 1);
    BOOST_CHECK_EQUAL(picks[0].endpoint, "good");
}

BOOST_AUTO_TEST_CASE(swarm_pipe_01_07_adaptive_window)
{
    using namespace modelnet;
    PickConfig cfg;
    cfg.min_inflight_bytes = PIECE_SIZE;
    cfg.max_inflight_bytes = 8 * PIECE_SIZE;
    cfg.global_inflight_ceiling = 8 * PIECE_SIZE;
    PeerMetrics fast;
    fast.throughput_bps = 100 * 1024 * 1024;
    PeerMetrics slow;
    slow.throughput_bps = 50 * 1024;
    BOOST_CHECK_GT(RequestWindowBytes(fast, cfg), RequestWindowBytes(slow, cfg));
    PeerMetrics timed = fast;
    timed.timeout_count = 4;
    BOOST_CHECK_LT(RequestWindowBytes(timed, cfg), RequestWindowBytes(fast, cfg));
    PeerMetrics rec = timed;
    rec.timeout_count = 0;
    BOOST_CHECK_GT(RequestWindowBytes(rec, cfg), RequestWindowBytes(timed, cfg));
    std::vector<SourceAvailability> srcs;
    srcs.push_back(MakeSrc("hog", 0, 1, 9));
    srcs.push_back(MakeSrc("other", 0, 1, 9));
    srcs.push_back(MakeSrc("rare", 0, 0, 1));
    std::map<std::string, PeerMetrics> metrics;
    metrics["hog"].throughput_bps = 1e9;
    metrics["hog"].inflight_bytes = 2 * PIECE_SIZE;
    metrics["other"].throughput_bps = 1e6;
    metrics["rare"].throughput_bps = 1;
    std::vector<uint32_t> missing = {0, 1, 2, 3, 4};
    cfg.max_assignments = 8;
    cfg.global_inflight_ceiling = 64 * PIECE_SIZE;
    const auto picks = PickRarestFirst(0, 10, missing, srcs, metrics, {}, {}, cfg);
    int hog = 0, other = 0, rare = 0;
    bool got_rare = false;
    for (const auto& p : picks) {
        if (p.endpoint == "hog") ++hog;
        if (p.endpoint == "other") ++other;
        if (p.endpoint == "rare") ++rare;
        if (p.piece_index == 0 && p.endpoint == "rare") got_rare = true;
    }
    BOOST_CHECK_GT(picks.size(), 0);
    BOOST_CHECK(got_rare);
    BOOST_CHECK(hog == 0 || other > 0);
}

BOOST_AUTO_TEST_CASE(swarm_ps_01_verified_piece_without_index)
{
    const fs::path tmp = m_path_root / "swarm-ps";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto st = TinySafeTensors(0x21);
    fs::create_directories(tmp / "src");
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err), err);
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_REQUIRE(cat.GetVerifiedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size, err));
    modelnet::ModelCatalog cat2{tmp / "dst", 8 << 20};
    UniValue man;
    BOOST_REQUIRE(cat.GetManifest(imported.model_id, man, err));
    BOOST_REQUIRE_MESSAGE(cat2.InstallFromManifest(man, err, /*complete=*/false), err);
    BOOST_REQUIRE_MESSAGE(cat2.PutFetchedPiece(imported.artifact_id, 0, 0, bytes, proof, file_size,
                                     imported.core.files[0].pieces_root, err), err);
    std::vector<unsigned char> again;
    std::vector<modelnet::Digest48> proof2;
    uint64_t fs2 = 0;
    BOOST_REQUIRE_MESSAGE(cat2.GetVerifiedPiece(imported.artifact_id, 0, 0, again, proof2, fs2, err), err);
    BOOST_CHECK(again == bytes);
}

BOOST_AUTO_TEST_CASE(swarm_ps_02_unverified_temp_not_servable)
{
    const fs::path tmp = m_path_root / "swarm-ps-tmp";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto st = TinySafeTensors(0x22);
    fs::create_directories(tmp / "src");
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));
    fs::create_directories(cat.Store().Root() / "tmp");
    {
        std::ofstream junk(cat.Store().Root() / "tmp" / "nope.tmp", std::ios::binary);
        junk << "not a piece";
    }
    std::vector<unsigned char> bytes;
    std::vector<modelnet::Digest48> proof;
    uint64_t file_size = 0;
    BOOST_CHECK(!cat.GetVerifiedPiece(imported.artifact_id, 0, 99, bytes, proof, file_size, err));
}

BOOST_AUTO_TEST_CASE(swarm_ps_03_04_partial_ranges_truthful)
{
    const fs::path tmp = m_path_root / "swarm-ps-ranges";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto st = TinySafeTensors(0x23);
    fs::create_directories(tmp / "src");
    {
        std::ofstream out(tmp / "src" / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    std::string err;
    modelnet::CatalogEntry imported;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(tmp / "src"), true, imported, err));
    modelnet::NativeRequest req;
    modelnet::NativeResponse resp;
    req.method = "POST";
    req.path = "/btx-model/2/availability";
    req.body = "{}";
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
    UniValue body;
    BOOST_REQUIRE(body.read(resp.body));
    BOOST_REQUIRE(body["local"]["models"][0]["complete"].get_bool());
}

BOOST_AUTO_TEST_CASE(swarm_px_01_08_provider_exchange)
{
    using namespace modelnet;
    ProviderExchange px;
    UniValue body(UniValue::VOBJ);
    UniValue recs(UniValue::VARR);
    UniValue one(UniValue::VOBJ);
    one.pushKV("endpoint", "203.0.113.9:29447");
    one.pushKV("service_id", "ab");
    recs.push_back(one);
    body.pushKV("providers", recs);
    std::vector<ProviderHint> acc;
    std::string err;
    BOOST_REQUIRE(px.Ingest("198.51.100.1:29447", body, 1000, acc, err));
    BOOST_REQUIRE_EQUAL(acc.size(), 1);
    BOOST_CHECK_EQUAL(px.Stats().accepted, 1);
    acc.clear();
    BOOST_REQUIRE(px.Ingest("198.51.100.1:29447", body, 1001, acc, err));
    BOOST_CHECK_EQUAL(px.Stats().duplicates, 1);
    UniValue wallet(UniValue::VOBJ);
    UniValue wrecs(UniValue::VARR);
    UniValue w(UniValue::VOBJ);
    w.pushKV("endpoint", "203.0.113.9:8332");
    wrecs.push_back(w);
    wallet.pushKV("providers", wrecs);
    BOOST_CHECK(px.Ingest("198.51.100.1:29447", wallet, 1002, acc, err));
    BOOST_CHECK_EQUAL(acc.size(), 0);
    UniValue flood(UniValue::VOBJ);
    UniValue many(UniValue::VARR);
    for (int i = 0; i < 40; ++i) {
        UniValue x(UniValue::VOBJ);
        x.pushKV("endpoint", "203.0.113." + std::to_string(i) + ":29447");
        many.push_back(x);
    }
    flood.pushKV("providers", many);
    BOOST_CHECK(!px.Ingest("198.51.100.1:29447", flood, 2000, acc, err) || acc.size() <= 16);
    px.Expire(1000 + PEX_DEFAULT_TTL_MS + 1);
    BOOST_CHECK(px.Recent(1000 + PEX_DEFAULT_TTL_MS + 1).empty());
    UniValue self(UniValue::VOBJ);
    UniValue srecs(UniValue::VARR);
    UniValue sone(UniValue::VOBJ);
    sone.pushKV("endpoint", "198.51.100.1:29447");
    sone.pushKV("model_id", std::string(96, 'a'));
    srecs.push_back(sone);
    self.pushKV("providers", srecs);
    acc.clear();
    BOOST_REQUIRE(px.Ingest("198.51.100.1:29447", self, 3000, acc, err));
    BOOST_REQUIRE_EQUAL(acc.size(), 1);
    BOOST_CHECK_EQUAL(acc[0].endpoint, "198.51.100.1:29447");
    ProviderHint local;
    local.endpoint = "203.0.113.9:29447";
    local.model_id = std::string(96, 'b');
    local.expiry_ms = 4000 + PEX_DEFAULT_TTL_MS;
    px.NoteLocal(local);
    const UniValue adv = px.Advertise(4000, PEX_MAX_RECORDS_PER_MESSAGE);
    BOOST_REQUIRE(adv.exists("providers"));
    bool saw_local = false;
    for (const auto& p : adv["providers"].getValues()) {
        if (p["endpoint"].get_str() == "203.0.113.9:29447") saw_local = true;
    }
    BOOST_CHECK(saw_local);
}

BOOST_AUTO_TEST_CASE(swarm_nat_01_10_control_plane)
{
    using namespace modelnet;
    BOOST_CHECK(IsForbiddenControlPort(8332));
    BOOST_CHECK(IsForbiddenControlPort(18443));
    BOOST_CHECK(IsForbiddenControlPort(19334));
    BOOST_CHECK(IsForbiddenControlPort(19335));
    BOOST_CHECK(!IsForbiddenControlPort(29447));
    BOOST_CHECK(MappingWouldExposeControlPlane(8332));
    std::string err;
    BOOST_CHECK(IsForbiddenControlEndpoint("10.0.0.1:8332", err));
    BOOST_CHECK(!IsForbiddenControlEndpoint("10.0.0.1:29447", err));
    BOOST_CHECK(IsForbiddenRelayEndpoint("10.0.0.1:29447", err));
    BOOST_CHECK(IsForbiddenRelayEndpoint("127.0.0.1:29447", err));
    BOOST_CHECK(!IsForbiddenRelayEndpoint("203.0.113.1:29447", err));
    BOOST_CHECK(IsForbiddenPexEndpoint("10.0.0.1:29447", err));
    BOOST_CHECK(IsForbiddenPexEndpoint("127.0.0.1:29447", err));
    BOOST_CHECK(!IsForbiddenPexEndpoint("203.0.113.1:29447", err));
    BOOST_CHECK(!MayAdvertiseModelHost(true, false, false));
    BOOST_CHECK(MayAdvertiseModelHost(true, true, false));
    BOOST_CHECK(!MayAdvertiseModelHost(true, true, true));
    RelayConnectRequest rr;
    rr.endpoint = "10.0.0.1:29447";
    rr.expected_service_id = "aa";
    rr.presented_service_id = "bb";
    rr.reservation_id = "rsvp";
    BOOST_CHECK(!ValidateRelayConnect(rr, true, err));
    rr.presented_service_id = "aa";
    BOOST_CHECK(!ValidateRelayConnect(rr, true, err));
    rr.endpoint = "203.0.113.1:29447";
    rr.reservation_id.clear();
    BOOST_CHECK(!ValidateRelayConnect(rr, true, err));
    rr.reservation_id = "rsvp";
    BOOST_CHECK(ValidateRelayConnect(rr, true, err));
    BOOST_CHECK(!ValidateRelayConnect(rr, false, err));
    BOOST_CHECK(!ValidateRendezvous("10.0.0.1:8332", "", "", err));
}

BOOST_AUTO_TEST_CASE(swarm_ranges_pairs_and_invert)
{
    UniValue arr(UniValue::VARR);
    UniValue p(UniValue::VARR);
    p.push_back(0);
    p.push_back(39);
    arr.push_back(p);
    std::vector<modelnet::PieceRange> rs;
    std::string err;
    BOOST_REQUIRE(modelnet::ParsePieceRangesJson(arr, rs, err));
    BOOST_REQUIRE_EQUAL(rs.size(), 1);
    BOOST_CHECK_EQUAL(rs[0].first, 0U);
    BOOST_CHECK_EQUAL(rs[0].count, 40U);
    UniValue bad(UniValue::VARR);
    UniValue inv(UniValue::VARR);
    inv.push_back(9);
    inv.push_back(1);
    bad.push_back(inv);
    BOOST_CHECK(!modelnet::ParsePieceRangesJson(bad, rs, err));
}

BOOST_AUTO_TEST_CASE(swarm_extinction_labels)
{
    using namespace modelnet;
    SwarmSnapshot s;
    s.pieces_total = 10;
    s.pieces_missing = 1;
    s.min_piece_sources = 1;
    BOOST_CHECK_EQUAL(std::string(ExtinctionLabel(s)), "FRAGILE");
    s.min_piece_sources = 0;
    BOOST_CHECK_EQUAL(std::string(ExtinctionLabel(s)), "CURRENTLY_UNAVAILABLE");
}

BOOST_AUTO_TEST_SUITE_END()
