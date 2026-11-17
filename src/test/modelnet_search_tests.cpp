// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/protocol.h>
#include <modelnet/provider_route.h>
#include <modelnet/qualification.h>
#include <modelnet/search.h>
#include <random.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>
#include <chrono>
#include <fstream>
#ifndef WIN32
#include <unistd.h>
#endif
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

    ProviderObservation unnamed;
    unnamed.provider_id = "dd";
    unnamed.complete = true;
    auto h4 = ComputeSwarmHealth(0, 0, {unnamed});
    BOOST_CHECK_EQUAL(static_cast<int>(h4.klass), static_cast<int>(AvailabilityClass::HIGH));
    BOOST_CHECK(h4.reconstructable_known);
    BOOST_CHECK(h4.reconstructable);
    ProviderObservation partial_only;
    partial_only.provider_id = "ee";
    partial_only.complete = false;
    auto h5 = ComputeSwarmHealth(0, 0, {partial_only});
    BOOST_CHECK_EQUAL(static_cast<int>(h5.klass), static_cast<int>(AvailabilityClass::HIGH));
    BOOST_CHECK(h5.reconstructable_known);
    BOOST_CHECK(!h5.reconstructable);

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

BOOST_AUTO_TEST_CASE(search_health_walks_only_the_model_pieces)
{
    using namespace modelnet;
    // Same counts as a walk over every piece and every range.
    const auto reference = [](uint32_t total, const std::vector<ProviderObservation>& obs) {
        std::vector<int> sources(total, 0);
        for (const auto& o : obs) {
            for (uint32_t i = 0; i < total; ++i) {
                for (const auto& r : o.ranges) {
                    if (RangeCovers(r, i)) {
                        ++sources[i];
                        break;
                    }
                }
            }
        }
        SwarmHealth h;
        h.min_piece_sources = total == 0 ? 0 : *std::min_element(sources.begin(), sources.end());
        for (const int n : sources) {
            if (n == 0) ++h.pieces_with_0_sources;
            else if (n == 1) ++h.pieces_with_1_source;
            else if (n == 2) ++h.pieces_with_2_sources;
        }
        return h;
    };
    FastRandomContext rng{/*fDeterministic=*/true};
    for (int round = 0; round < 2000; ++round) {
        const uint32_t total = 1 + rng.randrange(40);
        std::vector<ProviderObservation> obs(rng.randrange(5));
        for (size_t p = 0; p < obs.size(); ++p) {
            obs[p].provider_id = "p" + std::to_string(p);
            obs[p].ranges.resize(rng.randrange(6));
            for (auto& r : obs[p].ranges) {
                r.first = rng.randrange(50);
                r.count = 1 + rng.randrange(60);
            }
        }
        const SwarmHealth got = ComputeSwarmHealth(total, 0, obs);
        const SwarmHealth want = reference(total, obs);
        BOOST_REQUIRE_EQUAL(got.min_piece_sources, want.min_piece_sources);
        BOOST_REQUIRE_EQUAL(got.pieces_with_0_sources, want.pieces_with_0_sources);
        BOOST_REQUIRE_EQUAL(got.pieces_with_1_source, want.pieces_with_1_source);
        BOOST_REQUIRE_EQUAL(got.pieces_with_2_sources, want.pieces_with_2_sources);
        BOOST_REQUIRE_EQUAL(got.missing_piece_count, static_cast<uint32_t>(want.pieces_with_0_sources));
        BOOST_REQUIRE_EQUAL(got.reconstructable, want.pieces_with_0_sources == 0);
        BOOST_REQUIRE_EQUAL(got.reconstructable, UnionCoversAll(total, [&] {
            std::vector<std::vector<PieceRange>> all;
            for (const auto& o : obs) all.push_back(o.ranges);
            return all;
        }()));
    }
    // Ranges to the end of the piece index space, overlapping within one provider.
    ProviderObservation wide;
    wide.provider_id = "wide";
    wide.ranges = {{0, 0xFFFFFFFFu}, {7, 0xFFFFFFFFu - 7}};
    ProviderObservation narrow;
    narrow.provider_id = "narrow";
    narrow.ranges = {{3, 4}, {12, 100}};
    const SwarmHealth spanned = ComputeSwarmHealth(10, 0, {wide, narrow});
    const SwarmHealth spanned_want = reference(10, {wide, narrow});
    BOOST_CHECK_EQUAL(spanned.min_piece_sources, 1);
    BOOST_CHECK_EQUAL(spanned.pieces_with_1_source, 6);
    BOOST_CHECK_EQUAL(spanned.pieces_with_2_sources, 4);
    BOOST_CHECK_EQUAL(spanned.pieces_with_1_source, spanned_want.pieces_with_1_source);
    BOOST_CHECK_EQUAL(spanned.pieces_with_2_sources, spanned_want.pieces_with_2_sources);
    BOOST_CHECK(spanned.reconstructable);
    // Empty and wrapping ranges cover nothing, as in RangeCovers, and a provider
    // named twice counts once.
    ProviderObservation odd;
    odd.provider_id = "odd";
    odd.ranges = {{5, 0}, {1, 0xFFFFFFFFu}, {0xFFFFFFF0u, 0x20}};
    const SwarmHealth odd_health = ComputeSwarmHealth(10, 0, {odd, narrow, narrow});
    const SwarmHealth odd_want = reference(10, {odd, narrow});
    BOOST_CHECK_EQUAL(odd_health.providers_observed, 2);
    BOOST_CHECK_EQUAL(odd_health.pieces_with_0_sources, 6);
    BOOST_CHECK_EQUAL(odd_health.pieces_with_1_source, 4);
    BOOST_CHECK_EQUAL(odd_health.pieces_with_0_sources, odd_want.pieces_with_0_sources);
    BOOST_CHECK_EQUAL(odd_health.pieces_with_1_source, odd_want.pieces_with_1_source);
    BOOST_CHECK(!odd_health.reconstructable);

    // A peer's provider record may announce ranges far longer than the model.
    // Only the model's pieces count, and the work does not follow the span.
    const auto now_ms = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    };
    const fs::path root = m_path_root / "health-span";
    fs::create_directories(root);
    const fs::path model = root / "span.safetensors";
    std::string header = R"({"weight":{"dtype":"F32","shape":[256],"data_offsets":[0,1024]}})";
    header.append((8 - header.size() % 8) % 8, ' ');
    {
        std::ofstream file(model, std::ios::binary);
        const uint64_t header_size = header.size();
        for (int i = 0; i < 8; ++i) file.put(static_cast<char>(header_size >> (8 * i)));
        file << header << std::string(1024, '\x03');
        BOOST_REQUIRE(file.good());
    }
    ModelCatalog cat{root / "models", 1 << 20};
    CatalogEntry entry;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(model), false, entry, err), err);
    BOOST_REQUIRE(cat.Seed(entry.model_id, false, err));
    auto rpc = [&](const std::string& method, const UniValue& params) {
        UniValue req(UniValue::VOBJ), result;
        req.pushKV("method", method);
        req.pushKV("params", params);
        std::string code;
        BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, req, result, code, err), code + ": " + err);
        return result;
    };
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    ProviderRecord record;
    record.resource = entry.model_id;
    record.pubkey = pk;
    record.seq = 1;
    record.reachability_kind = "direct";
    record.endpoints = {"192.0.2.11:29447"};
    record.ranges.assign(PROVIDER_MAX_RANGES, PieceRange{0, 0xFFFFFFFFu});
    record.expiry_ms = now_ms() + 300000;
    BOOST_REQUIRE(SignProviderRecord(record, Span<const unsigned char>{sk.data(), sk.size()}, err));
    NativeRequest put;
    put.method = "POST";
    put.path = std::string(MODEL_HTTP_ROOT) + "ext/providers/put";
    put.body = ProviderRecordToJson(record).write();
    put.peer_addr = "span-fixture";
    NativeResponse response;
    BOOST_REQUIRE(HandleNativeRequest(cat, put, response));
    BOOST_REQUIRE_MESSAGE(response.status == 200, response.body);
    UniValue query(UniValue::VOBJ), search_params(UniValue::VARR), id_params(UniValue::VARR);
    query.pushKV("scope", "LOCAL");
    search_params.push_back(query);
    id_params.push_back(entry.model_id.Hex());
    const auto started = std::chrono::steady_clock::now();
    const auto search = rpc("searchmodels", search_params);
    const auto avail = rpc("getmodelavailability", id_params);
    const auto elapsed = std::chrono::steady_clock::now() - started;
    BOOST_REQUIRE_EQUAL(search["results"].size(), 1);
    BOOST_CHECK_EQUAL(search["results"][0]["availability"]["providers_partial"].getInt<int>(), 1);
    BOOST_CHECK(avail["reconstructable"].get_bool());
    BOOST_CHECK_EQUAL(avail["min_piece_sources"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(avail["pieces_with_0_sources"].getInt<int>(), 0);
    // Walking each announced range piece by piece took about 27 s per call here.
    BOOST_CHECK_MESSAGE(elapsed < std::chrono::seconds{5},
                        "health took " << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms");
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

// search-index.json also holds the operator's search policy (hidden models,
// muted publishers), and signed records from peers trigger saves. A file that
// is there but cannot be read must be kept, not replaced by the next save.
BOOST_AUTO_TEST_CASE(search_index_unreadable_file_is_kept)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "search-index-unreadable";
    fs::create_directories(dir);
    const fs::path path = dir / "search-index.json";
    const auto read_all = [](const fs::path& p) {
        std::ifstream in(p, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    };
    const auto write_all = [](const fs::path& p, const std::string& data) {
        std::ofstream out(p, std::ios::binary | std::ios::trunc);
        out << data;
    };
    const std::string muted(96, 'a');
    std::string err;
    SearchIndex idx;
    idx.MutePublisher(muted, true);
    BOOST_REQUIRE_MESSAGE(idx.Save(path, err), err);
    const std::string saved{read_all(path)};
    BOOST_REQUIRE(saved.find(muted) != std::string::npos);

    const std::string cut{saved.substr(0, saved.size() / 2)};
    write_all(path, cut);
    SearchIndex reloaded;
    BOOST_CHECK(reloaded.Load(path, 1, err));
    BOOST_CHECK(reloaded.Unreadable());
    BOOST_CHECK(!reloaded.Muted(muted));
    BOOST_CHECK(!reloaded.Save(path, err));
    BOOST_CHECK(err.find("cannot be read") != std::string::npos);
    BOOST_CHECK(read_all(path) == cut);

    write_all(path, saved);
    SearchIndex repaired;
    BOOST_CHECK(repaired.Load(path, 1, err));
    BOOST_CHECK(!repaired.Unreadable());
    BOOST_CHECK(repaired.Muted(muted));
    BOOST_CHECK(repaired.Save(path, err));

#ifndef WIN32
    // The same for a file that is there but cannot be opened.
    if (::geteuid() != 0) {
        fs::permissions(path, fs::perms::none);
        SearchIndex locked;
        BOOST_CHECK(locked.Load(path, 1, err));
        BOOST_CHECK(locked.Unreadable());
        BOOST_CHECK(!locked.Save(path, err));
        fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write);
        SearchIndex reopened;
        BOOST_CHECK(reopened.Load(path, 1, err));
        BOOST_CHECK(reopened.Muted(muted));
    }
#endif
    // A missing file still loads as an empty index that can be saved.
    SearchIndex fresh;
    BOOST_CHECK(fresh.Load(dir / "absent.json", 1, err));
    BOOST_CHECK(!fresh.Unreadable());
    BOOST_CHECK(fresh.Save(dir / "absent.json", err));

    // A file without records still holds the policy.
    const fs::path policy_only = dir / "policy-only.json";
    {
        std::ofstream out(policy_only, std::ios::binary | std::ios::trunc);
        out << "{\"muted_publishers\":[\"" << muted << "\"]}";
    }
    SearchIndex policy;
    BOOST_CHECK(policy.Load(policy_only, 1, err));
    BOOST_CHECK(!policy.Unreadable());
    BOOST_CHECK(policy.Muted(muted));

    // A policy list of another type cannot be read, so the file is kept.
    const fs::path odd = dir / "odd-policy.json";
    const std::string odd_text{"{\"records\":[],\"hidden\":\"not a list\"}"};
    {
        std::ofstream out(odd, std::ios::binary | std::ios::trunc);
        out << odd_text;
    }
    SearchIndex odd_index;
    BOOST_CHECK(odd_index.Load(odd, 1, err));
    BOOST_CHECK(odd_index.Unreadable());
    BOOST_CHECK(!odd_index.Save(odd, err));
    BOOST_CHECK(read_all(odd) == odd_text);
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

// The participation tick stores the records of a peer's ext/search reply. The
// peer decides how often that reply holds a change, and each save writes the
// whole index, so the tick saves at most once per interval.
BOOST_AUTO_TEST_CASE(search_gossip_saves_the_index_at_most_once_per_interval)
{
    using namespace modelnet;
    const fs::path root = m_path_root / "gossip-save";
    fs::create_directories(root);
    ModelCatalog cat{root / "models", 1 << 20};
    const fs::path index = cat.Store().Root().parent_path() / "search-index.json";
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    Digest48 first;
    // The same 16 models each time, signed again with a higher sequence.
    const auto reply_at = [&](uint64_t sequence) {
        UniValue records(UniValue::VARR);
        for (int i = 0; i < 16; ++i) {
            ModelSearchRecord r;
            r.model_id.data[0] = 0x67;
            r.model_id.data[1] = static_cast<unsigned char>(i + 1);
            r.artifact_id = r.model_id;
            r.canonical_name = "gossip-" + std::to_string(i);
            r.display_name = r.canonical_name;
            r.pubkey = pk;
            r.published_at = 1;
            r.metadata_sequence = sequence;
            BOOST_REQUIRE_MESSAGE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err), err);
            if (i == 0) first = r.model_id;
            records.push_back(SearchRecordToJson(r));
        }
        UniValue reply(UniValue::VOBJ);
        reply.pushKV("records", records);
        return reply;
    };
    // The sequence of the first model as search-index.json holds it.
    const auto saved_sequence = [&]() -> int64_t {
        std::ifstream in(index, std::ios::binary);
        const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        UniValue snap;
        if (!snap.read(text) || !snap.exists("records")) return -1;
        for (const auto& rec : snap["records"].getValues()) {
            if (rec["model_id"].get_str() == first.Hex()) return rec["metadata_sequence"].getInt<int64_t>();
        }
        return -1;
    };
    // Ten minutes ahead, so a save by another case in this process is over an interval ago.
    const int64_t t0 = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 10 * 60 * 1000;
    BOOST_CHECK(StoreGossipSearchReply(cat, reply_at(1), "gossip-fixture", t0));
    BOOST_CHECK_EQUAL(saved_sequence(), 1);
    // A pull every 5 s that always brings changed records saves no more than once a minute.
    for (int k = 1; k < 12; ++k) {
        BOOST_CHECK(!StoreGossipSearchReply(cat, reply_at(1 + k), "gossip-fixture", t0 + k * 5000));
    }
    BOOST_CHECK_EQUAL(saved_sequence(), 1);
    // The first pull after the interval saves what came before, also when it brings nothing new.
    BOOST_CHECK(StoreGossipSearchReply(cat, reply_at(12), "gossip-fixture", t0 + SEARCH_GOSSIP_SAVE_INTERVAL_MS));
    BOOST_CHECK_EQUAL(saved_sequence(), 12);
    // Nothing new and nothing left to save: no save.
    BOOST_CHECK(!StoreGossipSearchReply(cat, reply_at(12), "gossip-fixture", t0 + 3 * SEARCH_GOSSIP_SAVE_INTERVAL_MS));
    // A clock that went back saves a change at once.
    BOOST_CHECK(StoreGossipSearchReply(cat, reply_at(13), "gossip-fixture", t0 + 1000));
    BOOST_CHECK_EQUAL(saved_sequence(), 13);
    // Without another pull, the helper's loop saves once the interval is over.
    const int64_t t1 = t0 + 1000;
    BOOST_CHECK(!StoreGossipSearchReply(cat, reply_at(14), "gossip-fixture", t1 + 1000));
    BOOST_CHECK(!FlushGossipSearchIndex(cat, t1 + 30000, /*force=*/false));
    BOOST_CHECK_EQUAL(saved_sequence(), 13);
    BOOST_CHECK(FlushGossipSearchIndex(cat, t1 + SEARCH_GOSSIP_SAVE_INTERVAL_MS, /*force=*/false));
    BOOST_CHECK_EQUAL(saved_sequence(), 14);
    // A stop saves what is left at once, and then nothing is left.
    const int64_t t2 = t1 + SEARCH_GOSSIP_SAVE_INTERVAL_MS;
    BOOST_CHECK(!StoreGossipSearchReply(cat, reply_at(15), "gossip-fixture", t2 + 5000));
    BOOST_CHECK(FlushGossipSearchIndex(cat, t2 + 6000, /*force=*/true));
    BOOST_CHECK_EQUAL(saved_sequence(), 15);
    BOOST_CHECK(!FlushGossipSearchIndex(cat, t2 + 7000, /*force=*/true));
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
        r.expires_at = 1'000'000'000;
        r.publisher_identity.data[0] = static_cast<unsigned char>((i & 0xff) + 1);
        r.publisher_identity.data[1] = static_cast<unsigned char>((i >> 8) & 0xff);
        r.publisher_identity.data[2] = static_cast<unsigned char>((i >> 16) & 0xff);
        BOOST_REQUIRE(idx.Put(r, 1, err));
    }
    SearchQuery q;
    q.text = "qwen coder";
    q.limit = 25;
    const auto hits = idx.Search(q, 1);
    BOOST_CHECK_GE(hits.size(), 1);
    BOOST_CHECK_LE(hits.size(), 25);
}

// Every search keeps its job (with its hits) for getsearchstatus; a runtime
// keeps the newest SEARCH_JOBS_KEPT of them.
BOOST_AUTO_TEST_CASE(search_jobs_are_bounded)
{
    using namespace modelnet;
    SearchIndex local, peer;
    SearchRuntime rt;
    rt.Bind(&local);
    SearchQuery q;
    q.text = "qwen";
    q.scope = SearchScope::NETWORK;
    SearchJob st;
    std::vector<std::string> ids;
    for (size_t i = 0; i < SEARCH_JOBS_KEPT + 8; ++i) {
        auto job = rt.Start(q, {&peer}, 1);
        ids.push_back(job.query_id);
        rt.Finish(job);
    }
    for (size_t i = 0; i < 8; ++i) BOOST_CHECK(!rt.Status(ids[i], st));
    for (size_t i = 8; i < ids.size(); ++i) BOOST_CHECK(rt.Status(ids[i], st));

    // A running search stays while finished ones can go, so it can still be
    // cancelled.
    auto running = rt.Start(q, {&peer}, 1);
    BOOST_CHECK_EQUAL(static_cast<int>(running.state), static_cast<int>(SearchJobState::RUNNING));
    BOOST_CHECK(!rt.Status(ids[8], st));
    for (size_t i = 0; i < SEARCH_JOBS_KEPT; ++i) {
        auto job = rt.Start(q, {&peer}, 1);
        ids.push_back(job.query_id);
        rt.Finish(job);
    }
    BOOST_CHECK(rt.Status(running.query_id, st));
    BOOST_CHECK(!rt.Status(ids[ids.size() - SEARCH_JOBS_KEPT], st));
    BOOST_CHECK(rt.Status(ids[ids.size() - SEARCH_JOBS_KEPT + 1], st));

    // When all kept jobs run, the oldest goes; it is kept again, as the
    // newest, when it finishes, and the oldest other one goes.
    std::vector<SearchJob> runs;
    for (size_t i = 0; i < SEARCH_JOBS_KEPT; ++i) runs.push_back(rt.Start(q, {&peer}, 1));
    BOOST_CHECK(!rt.Status(running.query_id, st));
    BOOST_CHECK(rt.Status(runs.front().query_id, st));
    rt.Finish(running);
    BOOST_CHECK(rt.Status(running.query_id, st));
    BOOST_CHECK_EQUAL(static_cast<int>(st.state), static_cast<int>(SearchJobState::COMPLETE));
    BOOST_CHECK(!rt.Status(runs.front().query_id, st));
    BOOST_CHECK(rt.Status(runs.back().query_id, st));
    BOOST_CHECK(rt.Cancel(runs.back().query_id));
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

// Finish counts each search once: a LOCAL search that Start counted as
// complete is not counted again (and does not lower the running count), and
// a search cancelled while it ran stays cancelled.
BOOST_AUTO_TEST_CASE(search_finish_counts_each_search_once)
{
    using namespace modelnet;
    SearchIndex local, peer;
    SearchRuntime rt;
    rt.Bind(&local);
    SearchQuery net;
    net.text = "qwen";
    net.scope = SearchScope::NETWORK;
    SearchQuery loc = net;
    loc.scope = SearchScope::LOCAL;

    auto running = rt.Start(net, {&peer}, 1);
    BOOST_CHECK_EQUAL(rt.Running(), 1);
    auto local_job = rt.Start(loc, {}, 1);
    BOOST_CHECK_EQUAL(rt.Completed(), 1);
    rt.Finish(local_job);
    BOOST_CHECK_EQUAL(rt.Completed(), 1);
    BOOST_CHECK_EQUAL(rt.Running(), 1);

    BOOST_REQUIRE(rt.Cancel(running.query_id));
    BOOST_CHECK_EQUAL(rt.Running(), 0);
    rt.Finish(running);
    BOOST_CHECK_EQUAL(rt.Running(), 0);
    BOOST_CHECK_EQUAL(rt.Completed(), 1);
    SearchJob st;
    BOOST_REQUIRE(rt.Status(running.query_id, st));
    BOOST_CHECK_EQUAL(static_cast<int>(st.state), static_cast<int>(SearchJobState::CANCELLED));

    auto other = rt.Start(net, {&peer}, 1);
    rt.Finish(other);
    BOOST_CHECK_EQUAL(rt.Running(), 0);
    BOOST_CHECK_EQUAL(rt.Completed(), 2);

    // A search cancelled while it ran whose job was dropped (all kept jobs
    // run) is still counted once.
    auto dropped = rt.Start(net, {&peer}, 1);
    BOOST_REQUIRE(rt.Cancel(dropped.query_id));
    for (size_t i = 0; i < SEARCH_JOBS_KEPT; ++i) (void)rt.Start(net, {&peer}, 1);
    BOOST_CHECK(!rt.Status(dropped.query_id, st));
    BOOST_CHECK_EQUAL(rt.Running(), static_cast<int>(SEARCH_JOBS_KEPT));
    rt.Finish(dropped);
    BOOST_CHECK_EQUAL(rt.Running(), static_cast<int>(SEARCH_JOBS_KEPT));
    BOOST_CHECK_EQUAL(rt.Completed(), 2);
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

BOOST_AUTO_TEST_CASE(search_quota_charges_the_signer)
{
    using namespace modelnet;
    std::string err;
    std::vector<unsigned char> own_pk, own_sk, other_pk, other_sk;
    BOOST_REQUIRE(GenerateMlDsa44(own_pk, own_sk, err));
    BOOST_REQUIRE(GenerateMlDsa44(other_pk, other_sk, err));
    SearchIndex idx;
    const auto own = MakeRec("Own", own_pk, own_sk, 1);
    BOOST_REQUIRE_MESSAGE(idx.Put(own, 1, err), err);

    // Another key signs records that name this publisher as theirs, as a peer's
    // search or feed reply can carry them.
    auto claim = [&](int i) {
        ModelSearchRecord r;
        r.model_id.data[0] = 2;
        r.model_id.data[1] = static_cast<unsigned char>(i);
        r.canonical_name = "claim" + std::to_string(i);
        r.display_name = r.canonical_name;
        r.pubkey = other_pk;
        r.publisher_identity = own.publisher_identity;
        r.expires_at = 1'000'000;
        BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{other_sk.data(), other_sk.size()}, err));
        return r;
    };
    for (int i = 1; i <= 63; ++i) {
        BOOST_REQUIRE_MESSAGE(idx.Put(claim(i), 1, err, "203.0.113.7:29447"), err);
    }

    // They count against the key that signed them, not against this publisher.
    const auto next = MakeRec("Own next", own_pk, own_sk, 3);
    BOOST_CHECK_MESSAGE(idx.Put(next, 1, err), err);
    BOOST_CHECK_MESSAGE(idx.Put(claim(64), 1, err, "203.0.113.7:29447"), err);
    BOOST_CHECK(!idx.Put(claim(65), 1, err, "203.0.113.7:29447"));
    BOOST_CHECK_EQUAL(err, "publisher spam");
}

// The quota limits how many records one key keeps in the index. Records that
// expired and were pruned counted on: 64 records seen since the start refused
// every new model of that key until btx-modeld restarted.
BOOST_AUTO_TEST_CASE(search_quota_counts_live_records)
{
    using namespace modelnet;
    std::string err;
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    const auto rec = [&](int i, int64_t expires_at) {
        ModelSearchRecord r;
        r.model_id.data[0] = 3;
        r.model_id.data[1] = static_cast<unsigned char>(i);
        r.canonical_name = "live" + std::to_string(i);
        r.display_name = r.canonical_name;
        r.pubkey = pk;
        r.expires_at = expires_at;
        BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
        return r;
    };
    SearchIndex idx;
    for (int i = 0; i < 64; ++i) BOOST_REQUIRE_MESSAGE(idx.Put(rec(i, 1000), 1, err, "203.0.113.7:29447"), err);
    BOOST_CHECK(!idx.Put(rec(64, 1000), 1, err, "203.0.113.7:29447"));
    BOOST_CHECK_EQUAL(err, "publisher spam");

    // All 64 have expired; the next Put prunes them and the key may publish again.
    BOOST_CHECK_MESSAGE(idx.Put(rec(65, 100'000), 2000, err, "203.0.113.7:29447"), err);
    for (int i = 0; i < 64; ++i) BOOST_CHECK(idx.Get(rec(i, 1000).model_id) == nullptr);
    BOOST_CHECK(idx.Get(rec(65, 100'000).model_id) != nullptr);

    // 64 live records still fill the quota.
    for (int i = 66; i < 129; ++i) BOOST_REQUIRE_MESSAGE(idx.Put(rec(i, 100'000), 2000, err, "203.0.113.7:29447"), err);
    BOOST_CHECK(!idx.Put(rec(129, 100'000), 2000, err, "203.0.113.7:29447"));
    BOOST_CHECK_EQUAL(err, "publisher spam");
}

BOOST_AUTO_TEST_CASE(search_unsigned_expiry_quota_and_save)
{
    using namespace modelnet;
    std::string err;
    SearchIndex idx;
    ModelSearchRecord open;
    open.model_id.data[0] = 1;
    open.canonical_name = "open";
    open.display_name = "open";
    open.signed_ok = true;
    BOOST_CHECK(!idx.Put(open, 1, err));
    BOOST_CHECK_EQUAL(err, "unsigned expiry");
    BOOST_CHECK(idx.Get(open.model_id) == nullptr);

    ModelSearchRecord stale = open;
    stale.model_id.data[0] = 2;
    stale.expires_at = 5;
    stale.signed_ok = true;
    BOOST_CHECK(!idx.Put(stale, 10, err));
    BOOST_CHECK_EQUAL(err, "expired");

    ModelSearchRecord local = open;
    local.model_id.data[0] = 3;
    local.local_catalog = true;
    local.signed_ok = true;
    BOOST_REQUIRE(idx.Put(local, 1, err));
    BOOST_CHECK(idx.Get(local.model_id)->local_catalog);
    BOOST_CHECK(!idx.Get(local.model_id)->signed_ok);

    ModelSearchRecord soon;
    soon.model_id.data[0] = 4;
    soon.canonical_name = "soon";
    soon.display_name = "soon";
    soon.expires_at = 50;
    BOOST_REQUIRE(idx.Put(soon, 1, err));
    ModelSearchRecord later;
    later.model_id.data[0] = 5;
    later.canonical_name = "later";
    later.display_name = "later";
    later.expires_at = 1'000'000'000;
    BOOST_REQUIRE(idx.Put(later, 100, err));
    BOOST_CHECK(idx.Get(soon.model_id) == nullptr);
    BOOST_CHECK(idx.Get(later.model_id) != nullptr);

    SearchIndex anon;
    for (int i = 0; i < 64; ++i) {
        ModelSearchRecord r;
        r.model_id.data[0] = static_cast<unsigned char>(i + 1);
        r.canonical_name = "a" + std::to_string(i);
        r.display_name = r.canonical_name;
        r.expires_at = 1'000'000'000;
        BOOST_REQUIRE_MESSAGE(anon.Put(r, 1, err), err);
    }
    ModelSearchRecord overflow;
    overflow.model_id.data[1] = 1;
    overflow.canonical_name = "overflow";
    overflow.display_name = "overflow";
    overflow.expires_at = 1'000'000'000;
    BOOST_CHECK(!anon.Put(overflow, 1, err));
    BOOST_CHECK_EQUAL(err, "publisher spam");
    BOOST_REQUIRE_MESSAGE(anon.Put(overflow, 1, err, "203.0.113.9:29447"), err);
    ModelSearchRecord again = overflow;
    again.short_description = "same model";
    BOOST_REQUIRE(anon.Put(again, 1, err, "203.0.113.9:29447"));

    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    auto signed_rec = MakeRec("Kept", pk, sk, 9);
    BOOST_REQUIRE(idx.Put(signed_rec, 1, err));
    ModelSearchRecord peer = later;
    peer.signed_ok = true;
    BOOST_REQUIRE(idx.Put(peer, 100, err));
    BOOST_CHECK(!idx.Get(peer.model_id)->signed_ok);

    const fs::path path = m_path_root / "search-unsigned.json";
    BOOST_REQUIRE(idx.Save(path, err));
    std::ifstream in(path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    BOOST_CHECK(raw.find("later") == std::string::npos);
    BOOST_CHECK(raw.find("Kept") != std::string::npos);
    BOOST_CHECK(raw.find("local_catalog") != std::string::npos);
    SearchIndex loaded;
    BOOST_REQUIRE(loaded.Load(path, 1, err));
    BOOST_CHECK(loaded.Get(peer.model_id) == nullptr);
    BOOST_CHECK(loaded.Get(local.model_id) != nullptr);
    BOOST_CHECK(loaded.Get(local.model_id)->local_catalog);
    BOOST_CHECK(!loaded.Get(local.model_id)->signed_ok);
    BOOST_CHECK(loaded.Get(signed_rec.model_id)->signed_ok);
}

// FindByAlias returned the first record in model id order that named the
// alias, whoever signed it, also a hidden or muted one: a peer could take an
// alias this node's own model uses.
BOOST_AUTO_TEST_CASE(alias_resolves_own_records_first_and_refuses_a_clash)
{
    using namespace modelnet;
    std::string err;
    std::vector<unsigned char> own_pk, own_sk, a_pk, a_sk, b_pk, b_sk;
    BOOST_REQUIRE(GenerateMlDsa44(own_pk, own_sk, err));
    BOOST_REQUIRE(GenerateMlDsa44(a_pk, a_sk, err));
    BOOST_REQUIRE(GenerateMlDsa44(b_pk, b_sk, err));
    SearchIndex idx;
    const auto put = [&](uint8_t tag, const std::string& alias, const std::vector<unsigned char>& pk,
                         std::vector<unsigned char>& sk, bool own) {
        ModelSearchRecord r;
        r.model_id.data[0] = tag;
        r.artifact_id.data[0] = static_cast<unsigned char>(tag + 1);
        r.canonical_name = "alias" + std::to_string(tag);
        r.display_name = r.canonical_name;
        r.aliases = {alias};
        r.pubkey = pk;
        r.expires_at = 1'000'000;
        BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
        r.local_catalog = own;
        BOOST_REQUIRE_MESSAGE(idx.Put(r, 1, err), err);
        return r;
    };

    put(0x10, "team-model", a_pk, a_sk, false);
    const auto own = put(0x20, "team-model", own_pk, own_sk, true);
    const ModelSearchRecord* hit = idx.FindByAlias("team-model", 2);
    BOOST_REQUIRE(hit != nullptr);
    BOOST_CHECK(hit->model_id == own.model_id);
    // The operator can still name an own model it hid (unhidesearchmodel).
    idx.Hide(own.model_id, true);
    hit = idx.FindByAlias("team-model", 2);
    BOOST_REQUIRE(hit != nullptr);
    BOOST_CHECK(hit->model_id == own.model_id);
    idx.Hide(own.model_id, false);

    put(0x30, "two-keys", a_pk, a_sk, false);
    put(0x31, "two-keys", b_pk, b_sk, false);
    bool ambiguous = false;
    BOOST_CHECK(idx.FindByAlias("two-keys", 2, &ambiguous) == nullptr);
    BOOST_CHECK(ambiguous);

    const auto solo = put(0x40, "solo", b_pk, b_sk, false);
    BOOST_REQUIRE(idx.FindByAlias("solo", 2) != nullptr);
    idx.Hide(solo.model_id, true);
    BOOST_CHECK(idx.FindByAlias("solo", 2) == nullptr);
    idx.Hide(solo.model_id, false);
    idx.MutePublisher(solo.publisher_identity.Hex(), true);
    BOOST_CHECK(idx.FindByAlias("solo", 2) == nullptr);
    idx.MutePublisher(solo.publisher_identity.Hex(), false);
    BOOST_CHECK(idx.FindByAlias("solo", 2) != nullptr);
    BOOST_CHECK(idx.FindByAlias("solo", 1'000'000) == nullptr);
}

BOOST_AUTO_TEST_CASE(search_cap_and_local_records)
{
    // The index cap limits what peers can add; this node's own records still
    // get in. A newer version of a record this node signed stays local; a
    // record from another key that replaces the catalog stub does not.
    using namespace modelnet;
    std::string err;
    SearchIndex idx;
    idx.SetCap(1);
    ModelSearchRecord remote;
    remote.model_id.data[0] = 1;
    remote.canonical_name = "remote";
    remote.display_name = "remote";
    remote.expires_at = 1'000'000'000;
    BOOST_REQUIRE_MESSAGE(idx.Put(remote, 1, err, "203.0.113.5:29447"), err);
    ModelSearchRecord second = remote;
    second.model_id.data[0] = 2;
    BOOST_CHECK(!idx.Put(second, 1, err, "203.0.113.5:29447"));
    BOOST_CHECK_EQUAL(err, "index cap");
    ModelSearchRecord stub;
    stub.model_id.data[0] = 3;
    stub.canonical_name = "stub";
    stub.display_name = "stub";
    stub.local_catalog = true;
    BOOST_REQUIRE_MESSAGE(idx.Put(stub, 1, err), err);

    std::vector<unsigned char> peer_pk, peer_sk, own_pk, own_sk;
    BOOST_REQUIRE(GenerateMlDsa44(peer_pk, peer_sk, err));
    BOOST_REQUIRE(GenerateMlDsa44(own_pk, own_sk, err));
    // Another key's record for the stub's model replaces the stub and is not local.
    const auto peer = MakeRec("peer", peer_pk, peer_sk, 3);
    BOOST_REQUIRE_MESSAGE(idx.Put(peer, 1, err, "203.0.113.5:29447"), err);
    BOOST_CHECK(idx.Get(stub.model_id)->signed_ok);
    BOOST_CHECK(!idx.Get(stub.model_id)->local_catalog);

    // A record this node signed for its own model, then its next version.
    auto own = MakeRec("own", own_pk, own_sk, 4);
    own.local_catalog = true;
    BOOST_REQUIRE_MESSAGE(idx.Put(own, 1, err), err);
    auto next = own;
    next.local_catalog = false;
    next.metadata_sequence = own.metadata_sequence + 1;
    next.short_description = "next";
    BOOST_REQUIRE(SignSearchRecord(next, Span<const unsigned char>{own_sk.data(), own_sk.size()}, err));
    next.signed_ok = true;
    BOOST_REQUIRE_MESSAGE(idx.Put(next, 1, err), err);
    BOOST_CHECK_EQUAL(idx.Get(own.model_id)->short_description, "next");
    BOOST_CHECK(idx.Get(own.model_id)->local_catalog);
}

BOOST_AUTO_TEST_CASE(search_refreshes_signed_provider_observations)
{
    using namespace modelnet;
    const auto now_ms = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    };
    for (const bool initially_complete : {false, true}) {
        const fs::path root = m_path_root / (initially_complete ? "refresh-complete" : "refresh-partial");
        fs::create_directories(root);
        const fs::path model = root / "refresh.safetensors";
        std::string header = R"({"weight":{"dtype":"F32","shape":[256],"data_offsets":[0,1024]}})";
        header.append((8 - header.size() % 8) % 8, ' ');
        {
            std::ofstream file(model, std::ios::binary);
            const uint64_t header_size = header.size();
            for (int i = 0; i < 8; ++i) file.put(static_cast<char>(header_size >> (8 * i)));
            file << header << std::string(1024, initially_complete ? '\x01' : '\x02');
            BOOST_REQUIRE(file.good());
        }
        ModelCatalog cat{root / "models", 1 << 20};
        CatalogEntry entry;
        std::string err;
        BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(model), false, entry, err), err);
        BOOST_REQUIRE(cat.Seed(entry.model_id, false, err));
        auto rpc = [&](const std::string& method, const UniValue& params) {
            UniValue req(UniValue::VOBJ), result;
            req.pushKV("method", method);
            req.pushKV("params", params);
            std::string code;
            BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, req, result, code, err), code + ": " + err);
            return result;
        };
        auto native = [&](const std::string& route, const UniValue& body, int status) {
            NativeRequest req;
            req.method = "POST";
            req.path = std::string(MODEL_HTTP_ROOT) + "ext/providers/" + route;
            req.body = body.write();
            req.peer_addr = "signed-refresh-fixture";
            NativeResponse response;
            BOOST_REQUIRE(HandleNativeRequest(cat, req, response));
            BOOST_REQUIRE_MESSAGE(response.status == status, response.body);
            UniValue result;
            BOOST_REQUIRE(result.read(response.body));
            return result;
        };
        UniValue query(UniValue::VOBJ), search_params(UniValue::VARR), id_params(UniValue::VARR);
        query.pushKV("scope", "LOCAL");
        search_params.push_back(query);
        id_params.push_back(entry.model_id.Hex());
        rpc("searchmodels", search_params);
        BOOST_REQUIRE_EQUAL(rpc("getmodelproviders", id_params)["providers"].size(), 0);
        std::vector<unsigned char> pk, sk;
        BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
        ProviderRecord record;
        record.resource = entry.model_id;
        record.pubkey = pk;
        record.seq = 10;
        record.complete = initially_complete;
        record.reachability_kind = "direct";
        record.endpoints = {"192.0.2.10:29447"};
        record.ranges = {{0, 1}};
        record.expiry_ms = now_ms() + 300000;
        auto put = [&](int status) {
            BOOST_REQUIRE(SignProviderRecord(record, Span<const unsigned char>{sk.data(), sk.size()}, err));
            return native("put", ProviderRecordToJson(record), status);
        };
        put(200);
        rpc("searchmodels", search_params);
        BOOST_REQUIRE_EQUAL(rpc("getmodelproviders", id_params)["providers"].size(), 1);
        BOOST_CHECK_EQUAL(rpc("getmodelproviders", id_params)["providers"][0]["complete"].get_bool(), initially_complete);
        record.seq = 11;
        record.complete = !initially_complete;
        record.reachability_kind = "relay";
        put(200);
        UniValue lookup(UniValue::VOBJ);
        lookup.pushKV("resource", entry.model_id.Hex());
        auto cached = native("get", lookup, 200);
        BOOST_REQUIRE_EQUAL(cached["records"].size(), 1);
        BOOST_CHECK_EQUAL(cached["records"][0]["seq"].getInt<int>(), 11);
        BOOST_CHECK_EQUAL(cached["records"][0]["complete"].get_bool(), !initially_complete);
        const auto search = rpc("searchmodels", search_params);
        BOOST_REQUIRE_EQUAL(search["results"].size(), 1);
        BOOST_CHECK_EQUAL(search["results"][0]["model_id"].get_str(), entry.model_id.Hex());
        BOOST_CHECK_EQUAL(search["results"][0]["availability"]["providers_complete"].getInt<int>(), initially_complete ? 0 : 1);
        auto view = rpc("getmodelproviders", id_params);
        BOOST_REQUIRE_EQUAL(view["providers"].size(), 1);
        BOOST_CHECK_EQUAL(view["providers"][0]["complete"].get_bool(), !initially_complete);
        BOOST_CHECK(view["providers"][0]["relayed"].get_bool());
        BOOST_CHECK(!view["providers"][0]["direct"].get_bool());
        BOOST_CHECK_EQUAL(rpc("getmodelavailability", id_params)["providers_complete"].getInt<int>(), initially_complete ? 0 : 1);
        BOOST_CHECK_EQUAL(rpc("getmodelpeercount", id_params)["complete"].getInt<int>(), initially_complete ? 0 : 1);
        record.seq = 9;
        record.complete = initially_complete;
        const auto rejected = put(403);
        BOOST_CHECK(rejected.write().find("sequence rollback") != std::string::npos);
        cached = native("get", lookup, 200);
        BOOST_CHECK_EQUAL(cached["records"][0]["seq"].getInt<int>(), 11);
        rpc("searchmodels", search_params);
        BOOST_CHECK_EQUAL(rpc("getmodelproviders", id_params)["providers"][0]["complete"].get_bool(), !initially_complete);
    }
}

BOOST_AUTO_TEST_CASE(search_provider_observations_end_with_their_record)
{
    using namespace modelnet;
    const auto now_ms = [] {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    };
    const fs::path root = m_path_root / "observation-expiry";
    fs::create_directories(root);
    const fs::path model = root / "expiry.safetensors";
    std::string header = R"({"weight":{"dtype":"F32","shape":[256],"data_offsets":[0,1024]}})";
    header.append((8 - header.size() % 8) % 8, ' ');
    {
        std::ofstream file(model, std::ios::binary);
        const uint64_t header_size = header.size();
        for (int i = 0; i < 8; ++i) file.put(static_cast<char>(header_size >> (8 * i)));
        file << header << std::string(1024, '\x04');
        BOOST_REQUIRE(file.good());
    }
    ModelCatalog cat{root / "models", 1 << 20};
    CatalogEntry entry;
    std::string err;
    BOOST_REQUIRE_MESSAGE(cat.ImportPath(fs::PathToString(model), false, entry, err), err);
    BOOST_REQUIRE(cat.Seed(entry.model_id, false, err));
    auto rpc = [&](const std::string& method, const UniValue& params) {
        UniValue req(UniValue::VOBJ), result;
        req.pushKV("method", method);
        req.pushKV("params", params);
        std::string code;
        BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, req, result, code, err), code + ": " + err);
        return result;
    };
    struct Key {
        std::vector<unsigned char> pk, sk;
    };
    Key short_key, long_key, swap_key;
    for (Key* k : {&short_key, &long_key, &swap_key}) BOOST_REQUIRE(GenerateMlDsa44(k->pk, k->sk, err));
    auto put = [&](const std::string& peer, const Key& key, uint64_t seq, int64_t expiry_ms) {
        const auto& pk = key.pk;
        const auto& sk = key.sk;
        ProviderRecord record;
        record.resource = entry.model_id;
        record.pubkey = pk;
        record.seq = seq;
        record.complete = true;
        record.reachability_kind = "direct";
        record.endpoints = {"192.0.2.12:29447"};
        record.ranges = {{0, 1}};
        record.expiry_ms = expiry_ms;
        BOOST_REQUIRE(SignProviderRecord(record, Span<const unsigned char>{sk.data(), sk.size()}, err));
        NativeRequest req;
        req.method = "POST";
        req.path = std::string(MODEL_HTTP_ROOT) + "ext/providers/put";
        req.body = ProviderRecordToJson(record).write();
        req.peer_addr = peer;
        NativeResponse response;
        BOOST_REQUIRE(HandleNativeRequest(cat, req, response));
        BOOST_REQUIRE_MESSAGE(response.status == 200, response.body);
        return record.service_id.Hex();
    };
    // Two providers from two peers: one record ends in a few seconds, one in five minutes.
    const int64_t short_expiry = now_ms() + 3000;
    put("expiry-short-fixture", short_key, 1, short_expiry);
    const std::string lasting = put("expiry-long-fixture", long_key, 1, now_ms() + 300000);
    UniValue query(UniValue::VOBJ), search_params(UniValue::VARR), id_params(UniValue::VARR);
    query.pushKV("scope", "LOCAL");
    search_params.push_back(query);
    id_params.push_back(entry.model_id.Hex());
    rpc("searchmodels", search_params);
    BOOST_REQUIRE_EQUAL(rpc("getmodelproviders", id_params)["providers"].size(), 2);
    BOOST_CHECK_EQUAL(rpc("getmodelavailability", id_params)["providers_complete"].getInt<int>(), 2);

    while (now_ms() <= short_expiry) UninterruptibleSleep(std::chrono::milliseconds{50});
    // The record has left the provider cache; its copy no longer counts either.
    const auto providers = rpc("getmodelproviders", id_params)["providers"];
    BOOST_REQUIRE_EQUAL(providers.size(), 1);
    BOOST_CHECK_EQUAL(providers[0]["provider_id"].get_str(), lasting);
    BOOST_CHECK_EQUAL(rpc("getmodelavailability", id_params)["providers_complete"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(rpc("getmodelpeercount", id_params)["complete"].getInt<int>(), 1);
    rpc("searchmodels", search_params);
    BOOST_CHECK_EQUAL(rpc("getmodelproviders", id_params)["providers"].size(), 1);

    // A provider that replaces its record with one that ends sooner: once that
    // record is gone from the cache, searchmodels drops the earlier copy too.
    const std::string swapped = put("expiry-swap-fixture", swap_key, 1, now_ms() + 300000);
    rpc("searchmodels", search_params);
    BOOST_REQUIRE_EQUAL(rpc("getmodelproviders", id_params)["providers"].size(), 2);
    const int64_t swap_expiry = now_ms() + 1000;
    BOOST_CHECK_EQUAL(put("expiry-swap-fixture", swap_key, 2, swap_expiry), swapped);
    while (now_ms() <= swap_expiry) UninterruptibleSleep(std::chrono::milliseconds{50});
    rpc("searchmodels", search_params);
    const auto after_swap = rpc("getmodelproviders", id_params)["providers"];
    BOOST_REQUIRE_EQUAL(after_swap.size(), 1);
    BOOST_CHECK_EQUAL(after_swap[0]["provider_id"].get_str(), lasting);
}

BOOST_AUTO_TEST_SUITE_END()
