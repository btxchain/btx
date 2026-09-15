// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/protocol.h>
#include <modelnet/qualification.h>
#include <modelnet/search.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_search_tests, BasicTestingSetup)

namespace {

modelnet::ModelSearchRecord MakeRec(const std::string& name, const std::vector<unsigned char>& pk,
                                     std::vector<unsigned char>& sk, uint8_t tag)
{
    using namespace modelnet;
    ModelSearchRecord r;
    r.model_id.data[0] = tag;
    r.artifact_id.data[0] = static_cast<unsigned char>(tag + 1);
    r.canonical_name = name;
    r.display_name = name;
    r.pubkey = pk;
    r.published_at = tag;
    r.expires_at = 1'000'000;
    std::string err;
    BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
    r.signed_ok = true;
    return r;
}

} // namespace

BOOST_AUTO_TEST_CASE(search_local_01_to_15)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    SearchIndex idx;
    auto a = MakeRec("Qwen Coder", pk, sk, 1);
    a.aliases = {"qwen-coder", "qwencoder"};
    a.tags = {"coding", "instruct"};
    a.languages = {"en", "ja"};
    a.architecture = "qwen2";
    a.format = "GGUF";
    a.quantization = "Q4_K_M";
    a.size_bytes = 19ull << 30;
    a.publisher_display_name = "alice";
    BOOST_REQUIRE(SignSearchRecord(a, Span<const unsigned char>{sk.data(), sk.size()}, err));
    a.signed_ok = true;
    BOOST_REQUIRE(idx.Put(a, 10, err));
    auto b = MakeRec("Vision Test", pk, sk, 2);
    b.format = "SafeTensors";
    b.family = "vision";
    BOOST_REQUIRE(SignSearchRecord(b, Span<const unsigned char>{sk.data(), sk.size()}, err));
    b.signed_ok = true;
    BOOST_REQUIRE(idx.Put(b, 10, err));

    SearchQuery q;
    q.text = "qwen coder";
    q.scope = SearchScope::LOCAL;
    auto hits = idx.Search(q, 10);
    BOOST_REQUIRE_GE(hits.size(), 1);
    BOOST_CHECK_EQUAL(hits[0].rec.canonical_name, "Qwen Coder");

    q.text = "qwencoder";
    BOOST_CHECK_GE(idx.Search(q, 10).size(), 1);
    q.text = "coding";
    BOOST_CHECK_GE(idx.Search(q, 10).size(), 1);
    q.text = "";
    q.filters.language = {"ja"};
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);
    q.filters = {};
    q.filters.publisher_name = "alice";
    BOOST_CHECK_GE(idx.Search(q, 10).size(), 1);
    q.filters = {};
    q.filters.architecture = "qwen2";
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);
    q.filters = {};
    q.filters.format = "GGUF";
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);
    q.filters = {};
    q.filters.quantization = "Q4_K_M";
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);
    q.filters = {};
    q.filters.min_size_bytes = 10ull << 30;
    q.filters.max_size_bytes = 20ull << 30;
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);

    BOOST_REQUIRE(idx.Put(a, 11, err));
    q.filters = {};
    q.text = "qwen";
    q.limit = 50;
    BOOST_CHECK_EQUAL(idx.Search(q, 11).size(), 1);

    q.text = "";
    q.filters = {};
    q.limit = 1;
    q.offset = 0;
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);
    q.offset = 1;
    q.limit = 1;
    BOOST_CHECK_EQUAL(idx.Search(q, 10).size(), 1);

    UniValue bad(UniValue::VOBJ);
    bad.pushKV("scope", "PLANET");
    SearchQuery qq;
    BOOST_CHECK(!ParseSearchQuery(bad, qq, err));

    ModelSearchRecord huge = a;
    huge.short_description.assign(SEARCH_DESC_MAX + 1, 'x');
    BOOST_CHECK(!ValidateSearchRecord(huge, err));

    BOOST_CHECK_EQUAL(NormalizeSearchText("Qwen   Coder!"), "qwen coder");
    q.filters = {};
    q.text = "qwen coder";
    q.sort = SearchSort::RELEVANCE;
    const auto r1 = idx.Search(q, 10);
    const auto r2 = idx.Search(q, 10);
    BOOST_REQUIRE_EQUAL(r1.size(), r2.size());
    if (!r1.empty()) BOOST_CHECK_EQUAL(r1[0].rec.model_id.Hex(), r2[0].rec.model_id.Hex());
}

BOOST_AUTO_TEST_CASE(search_sig_01_to_08)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk, pk2, sk2;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    BOOST_REQUIRE(GenerateMlDsa44(pk2, sk2, err));
    SearchIndex idx;
    auto r = MakeRec("Alpha", pk, sk, 3);
    BOOST_CHECK(VerifySearchRecord(r, 1, err));
    BOOST_CHECK(idx.Put(r, 1, err));

    auto forged = r;
    if (!forged.sig.empty()) forged.sig[0] ^= 0xff;
    BOOST_CHECK(!VerifySearchRecord(forged, 1, err));

    auto wrong = r;
    wrong.pubkey = pk2;
    wrong.signer_id = ResearchIdentityId(Span<const unsigned char>{pk2.data(), pk2.size()});
    BOOST_CHECK(!VerifySearchRecord(wrong, 1, err));

    auto older = r;
    older.metadata_sequence = 0;
    BOOST_REQUIRE(SignSearchRecord(older, Span<const unsigned char>{sk.data(), sk.size()}, err));
    older.signed_ok = true;
    BOOST_CHECK(!idx.Put(older, 2, err));

    auto expired = r;
    expired.expires_at = 5;
    BOOST_REQUIRE(SignSearchRecord(expired, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK(!VerifySearchRecord(expired, 10, err));

    BOOST_CHECK(idx.Tombstone(r.model_id, 9, 20, err) == false);
    auto tomb = r;
    tomb.tombstone = true;
    tomb.metadata_sequence = 9;
    BOOST_REQUIRE(SignSearchRecord(tomb, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK(idx.Put(tomb, 20, err));
    SearchQuery q;
    q.text = "alpha";
    BOOST_CHECK(idx.Search(q, 20).empty());

    ModelSearchRecord uns;
    uns.model_id = r.model_id;
    uns.display_name = "hack";
    uns.canonical_name = "hack";
    BOOST_CHECK(!idx.Put(uns, 21, err));
    BOOST_CHECK(UnsignedCannotOverrideSigned());
}

BOOST_AUTO_TEST_CASE(search_dir_01_to_10)
{
    using namespace modelnet;
    std::vector<ProviderObservation> obs;
    ProviderObservation a;
    a.provider_id = "aa";
    a.endpoint = "203.0.113.1:29447";
    a.complete = false;
    a.direct = true;
    PieceRange r0;
    r0.first = 0;
    r0.count = 5;
    a.ranges.push_back(r0);
    ProviderObservation b;
    b.provider_id = "bb";
    b.endpoint = "203.0.113.2:29447";
    b.complete = false;
    b.relayed = true;
    PieceRange r1;
    r1.first = 5;
    r1.count = 5;
    b.ranges.push_back(r1);
    obs.push_back(a);
    obs.push_back(b);
    auto h = ComputeSwarmHealth(10, 0, obs);
    BOOST_CHECK_EQUAL(h.providers_observed, 2);
    BOOST_CHECK_EQUAL(h.providers_complete, 0);
    BOOST_CHECK_EQUAL(h.providers_partial, 2);
    BOOST_CHECK(h.reconstructable);
    BOOST_CHECK_NE(std::string(AvailabilityClassName(h.klass)), "UNKNOWN");

    ProviderObservation only;
    only.provider_id = "cc";
    only.complete = true;
    PieceRange all;
    all.first = 0;
    all.count = 10;
    only.ranges.push_back(all);
    auto h2 = ComputeSwarmHealth(10, 0, {only});
    BOOST_CHECK(h2.fragile || h2.min_piece_sources == 1);
    BOOST_CHECK_EQUAL(static_cast<int>(h2.klass), static_cast<int>(AvailabilityClass::FRAGILE));

    auto h3 = ComputeSwarmHealth(10, 0, {});
    BOOST_CHECK_EQUAL(static_cast<int>(h3.klass), static_cast<int>(AvailabilityClass::UNKNOWN));
    BOOST_CHECK(!h3.reconstructable || !h3.reconstructable_known);

    SearchHit card;
    card.rec.display_name = "x";
    card.local.pinned = true;
    card.rec.release_state = "PUBLIC";
    card.rec.aliases = {"n"};
    card.provenance = {"publisher"};
    const UniValue d = DirectoryEntryJson(card);
    BOOST_CHECK(d["local"]["pinned"].get_bool());
    BOOST_CHECK_EQUAL(d["release"]["state"].get_str(), "PUBLIC");
    BOOST_CHECK(d.exists("publisher"));
}

BOOST_AUTO_TEST_CASE(search_index_01_to_10)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    SearchIndex idx;
    auto r = MakeRec("Beta", pk, sk, 4);
    BOOST_CHECK(idx.Put(r, 1, err));
    BOOST_CHECK_EQUAL(idx.Size(), 1);
    auto next = r;
    next.metadata_sequence = 2;
    next.short_description = "updated";
    BOOST_REQUIRE(SignSearchRecord(next, Span<const unsigned char>{sk.data(), sk.size()}, err));
    next.signed_ok = true;
    BOOST_CHECK(idx.Put(next, 2, err));
    BOOST_CHECK_EQUAL(idx.Get(r.model_id)->short_description, "updated");
    auto exp = r;
    exp.expires_at = 3;
    BOOST_REQUIRE(SignSearchRecord(exp, Span<const unsigned char>{sk.data(), sk.size()}, err));
    exp.signed_ok = true;
    SearchIndex idx2;
    BOOST_CHECK(idx2.Put(exp, 1, err));
    SearchQuery q;
    q.text = "beta";
    BOOST_CHECK(idx2.Search(q, 10).empty());
    UniValue snap = idx.ExportSince(0, 10);
    BOOST_CHECK(snap["records"].isArray());
    SearchIndex imported;
    for (const auto& recj : snap["records"].getValues()) {
        ModelSearchRecord parsed;
        BOOST_REQUIRE(SearchRecordFromJson(recj, parsed, err));
        parsed.signed_ok = true;
        BOOST_CHECK(imported.Put(parsed, 1, err));
    }
    UniValue junk(UniValue::VOBJ);
    junk.pushKV("type", "arbitrary");
    ModelSearchRecord bad;
    BOOST_CHECK(!SearchRecordFromJson(junk, bad, err));
    BOOST_CHECK(!SearchTouchesMonetaryConsensus());
}

BOOST_AUTO_TEST_CASE(search_net_01_to_13)
{
    using namespace modelnet;
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    SearchIndex local, peer, idxn;
    auto a = MakeRec("Qwen Coder Test A", pk, sk, 10);
    auto b = MakeRec("Qwen Coder Test B", pk, sk, 11);
    BOOST_REQUIRE(peer.Put(a, 1, err));
    BOOST_REQUIRE(idxn.Put(b, 1, err));
    SearchRuntime rt;
    rt.Bind(&local);
    SearchQuery q;
    q.text = "qwen coder";
    q.scope = SearchScope::NETWORK;
    q.limit = 25;
    auto job = rt.Start(q, {&peer, &idxn}, 1);
    BOOST_CHECK_EQUAL(static_cast<int>(job.state), static_cast<int>(SearchJobState::RUNNING));
    rt.Finish(job);
    BOOST_CHECK_EQUAL(static_cast<int>(job.state), static_cast<int>(SearchJobState::COMPLETE));
    BOOST_CHECK_GE(job.hits.size(), 2);
    BOOST_CHECK(!job.coverage.complete);

    SearchIndex many;
    BOOST_REQUIRE(many.Put(a, 1, err));
    std::vector<SearchIndex*> extras;
    SearchIndex copies[10];
    for (auto& c : copies) {
        BOOST_REQUIRE(c.Put(a, 1, err));
        extras.push_back(&c);
    }
    SearchRuntime rt2;
    rt2.Bind(&many);
    q.scope = SearchScope::NETWORK;
    const auto j2 = rt2.Start(q, extras, 1);
    int same = 0;
    for (const auto& h : j2.hits) {
        if (h.rec.model_id == a.model_id) ++same;
    }
    BOOST_CHECK_EQUAL(same, 1);

    QueryDedupe d;
    BOOST_CHECK(d.Admit("q1"));
    BOOST_CHECK(!d.Admit("q1"));
    BOOST_CHECK(ShouldForwardSearch(2, 0));
    BOOST_CHECK(!ShouldForwardSearch(0, 0));
    BOOST_CHECK(!ShouldForwardSearch(2, 4));

    SearchQuery loc;
    loc.scope = SearchScope::LOCAL;
    loc.text = "qwen";
    const auto j3 = rt.Start(loc, {&peer}, 1);
    BOOST_CHECK_EQUAL(j3.coverage.connected_peers_queried, 0);
    SearchJob st;
    BOOST_CHECK(rt.Status(job.query_id, st));
    BOOST_CHECK(rt.Cancel(job.query_id));

    BOOST_CHECK(SearchPeerTimedOut(SEARCH_PEER_TIMEOUT_MS, SEARCH_PEER_TIMEOUT_MS));
    BOOST_CHECK(SearchPeerTimedOut(SEARCH_PEER_TIMEOUT_MS + 1, SEARCH_PEER_TIMEOUT_MS));
    BOOST_CHECK(!SearchPeerTimedOut(0, SEARCH_PEER_TIMEOUT_MS));
    SearchCoverage cov;
    NoteSearchPeerTimeout(cov);
    BOOST_CHECK_EQUAL(cov.timed_out, 1);
    BOOST_CHECK(!cov.complete);
    SearchHit remote;
    remote.rec = a;
    remote.provenance = {"pex-peer"};
    SearchJob jmerge = job;
    MergeRemoteSearchHits(jmerge, {remote});
    BOOST_CHECK_GE(jmerge.hits.size(), 1);
}

BOOST_AUTO_TEST_CASE(search_scale_unsigned_2k)
{
    using namespace modelnet;
    SearchIndex idx;
    std::string err;
    for (int i = 0; i < 2000; ++i) {
        ModelSearchRecord r;
        r.model_id.data[0] = static_cast<unsigned char>(i & 0xff);
        r.model_id.data[1] = static_cast<unsigned char>((i >> 8) & 0xff);
        r.model_id.data[2] = static_cast<unsigned char>((i >> 16) & 0xff);
        r.canonical_name = (i % 7 == 0) ? "Qwen Coder Scale" : ("Model " + std::to_string(i));
        r.display_name = r.canonical_name;
        BOOST_REQUIRE(idx.Put(r, 1, err));
    }
    SearchQuery q;
    q.text = "qwen coder";
    q.limit = 25;
    const auto hits = idx.Search(q, 1);
    BOOST_CHECK_GE(hits.size(), 1);
    BOOST_CHECK_LE(hits.size(), 25);
}

BOOST_AUTO_TEST_CASE(search_rpc_more_methods)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "search-rpc2";
    fs::create_directories(tmp);
    ModelCatalog cat{tmp, 1 << 20};
    auto call = [&](const std::string& method, const UniValue& params) {
        UniValue req(UniValue::VOBJ);
        req.pushKV("method", method);
        req.pushKV("params", params);
        UniValue result;
        std::string code, e;
        BOOST_CHECK(DispatchHelperRpc(cat, req, result, code, e, nullptr));
        BOOST_CHECK(result.exists("schema_version"));
        return result;
    };
    UniValue empty(UniValue::VARR);
    BOOST_CHECK(call("getnetworkmodelstats", empty).exists("coverage_disclaimer"));
    BOOST_CHECK(call("browsemodels", empty).exists("results"));
    BOOST_CHECK(call("getsearchpeers", empty).exists("peers"));
    BOOST_CHECK(call("gettrendingmodels", empty).exists("metric"));
    NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = std::string(MODEL_HTTP_ROOT) + "ext/search";
    UniValue body(UniValue::VOBJ);
    body.pushKV("text", "qwen");
    body.pushKV("ttl", 2);
    nreq.body = body.write();
    NativeResponse nresp;
    BOOST_CHECK(HandleNativeRequest(cat, nreq, nresp));
    BOOST_CHECK_EQUAL(nresp.status, 200);
}

BOOST_AUTO_TEST_CASE(search_rpc_directory_entry)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "search-rpc";
    fs::create_directories(tmp);
    ModelCatalog cat{tmp, 1 << 20};
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "searchmodels");
    UniValue params(UniValue::VARR);
    UniValue q(UniValue::VOBJ);
    q.pushKV("text", "qwen");
    q.pushKV("scope", "LOCAL");
    params.push_back(q);
    req.pushKV("params", params);
    UniValue result;
    std::string code, e;
    BOOST_CHECK(DispatchHelperRpc(cat, req, result, code, e, nullptr));
    BOOST_CHECK(result.exists("coverage") || result.exists("results") || result.exists("models"));
    BOOST_CHECK(result.exists("schema_version"));
}

BOOST_AUTO_TEST_CASE(search_creator_publish_rpc)
{
    using namespace modelnet;
    const fs::path tmp = m_path_root / "search-creator";
    fs::create_directories(tmp);
    ModelCatalog cat{tmp, 1 << 20};
    UniValue meta(UniValue::VOBJ);
    meta.pushKV("display_name", "Creator Lab Model");
    meta.pushKV("canonical_name", "Creator Lab Model");
    meta.pushKV("short_description", "unix RPC publish path used by the GUI Publish tab");
    UniValue params(UniValue::VARR);
    params.push_back(std::string(96, 'a'));
    params.push_back(meta);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", "publishmodelsearchrecord");
    req.pushKV("params", params);
    UniValue result;
    std::string code, e;
    BOOST_CHECK(DispatchHelperRpc(cat, req, result, code, e, nullptr));
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result["wallet_key"].get_bool());
    UniValue q(UniValue::VOBJ);
    q.pushKV("text", "Creator Lab");
    q.pushKV("scope", "LOCAL");
    UniValue sp(UniValue::VARR);
    sp.push_back(q);
    UniValue sreq(UniValue::VOBJ);
    sreq.pushKV("method", "searchmodels");
    sreq.pushKV("params", sp);
    UniValue hits;
    BOOST_CHECK(DispatchHelperRpc(cat, sreq, hits, code, e, nullptr));
    BOOST_CHECK(hits.exists("results") || hits.exists("models"));
}

BOOST_AUTO_TEST_CASE(search_exactreplay_isolation)
{
    using namespace modelnet;
    BOOST_CHECK(!SearchTouchesMonetaryConsensus());
    BOOST_CHECK(!ModelWorkMayStarveExactReplay());
}

BOOST_AUTO_TEST_SUITE_END()
