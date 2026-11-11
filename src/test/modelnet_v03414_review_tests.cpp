// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// v0.34.14 re-review: free-grant single use (bca3ea11) and the new
// "undownloadable plaintext is not served" gate. Regtest/unit only.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/feed.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/model_watch.h>
#include <modelnet/resource_uri.h>
#include <modelnet/search.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <ctime>
#include <fstream>
#include <set>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_v03414_review_tests, BasicTestingSetup)

namespace {

modelnet::CatalogEntry ImportTiny(modelnet::ModelCatalog& cat)
{
    const fs::path src = cat.Store().Root().parent_path() / "src";
    fs::create_directories(src);
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    {
        std::ofstream out(src / "model.safetensors", std::ios::binary);
        out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    }
    modelnet::CatalogEntry imported;
    std::string err;
    BOOST_REQUIRE(cat.ImportPath(fs::PathToString(src), true, imported, err));
    BOOST_REQUIRE(cat.Seed(imported.model_id, true, err));
    return imported;
}

/** POST ext/free/grant as `peer`. Returns the HTTP status; fills gj on 200. */
int Grant(modelnet::ModelCatalog& cat, const modelnet::CatalogEntry& e, const std::string& peer, UniValue& gj)
{
    modelnet::NativeRequest nreq;
    nreq.method = "POST";
    nreq.path = "/btx-model/2/ext/free/grant";
    nreq.peer_addr = peer;
    UniValue req(UniValue::VOBJ);
    req.pushKV("model_id", e.model_id.Hex());
    req.pushKV("first_piece", 0);
    req.pushKV("piece_count", 1);
    nreq.body = req.write();
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    if (nresp.status == 200) BOOST_REQUIRE(gj.read(nresp.body));
    return nresp.status;
}

int GetPiece0(modelnet::ModelCatalog& cat, const modelnet::CatalogEntry& e, const UniValue& gj, std::string* body = nullptr)
{
    modelnet::NativeRequest nreq;
    nreq.method = "GET";
    nreq.path = "/btx-model/2/transfers/" + e.artifact_id.Hex() + "/pieces/0/0";
    nreq.headers = {
        {"X-BTX-Grant-Payload", gj["payload_hex"].get_str()},
        {"X-BTX-Grant-Sig", gj["sig_hex"].get_str()},
        {"X-BTX-Grant-Pubkey", gj["pubkey_hex"].get_str()},
    };
    modelnet::NativeResponse nresp;
    BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, nreq, nresp));
    if (body) *body = nresp.body;
    return nresp.status;
}

bool Rpc(modelnet::ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& out, std::string& code, std::string& err)
{
    UniValue rpc(UniValue::VOBJ);
    rpc.pushKV("method", method);
    rpc.pushKV("params", params);
    return modelnet::DispatchHelperRpc(cat, rpc, out, code, err);
}

std::string RandHex48()
{
    FastRandomContext rng;
    const std::vector<unsigned char> b = rng.randbytes(48);
    return HexStr(b);
}

fs::path HelperDirOf(modelnet::ModelCatalog& cat)
{
    // grant_redeems.json lives next to the helper's other state.
    return cat.Store().Root().parent_path();
}

fs::path FindFile(const fs::path& root, const std::string& name)
{
    for (const auto& ent : fs::recursive_directory_iterator(root)) {
        if (ent.is_regular_file() && fs::PathToString(ent.path().filename()) == name) return ent.path();
    }
    return {};
}

/** createmodelrelease for `e` (no helper identity: the campaign is unsigned). */
bool CreateRelease(modelnet::ModelCatalog& cat, const modelnet::CatalogEntry& e, UniValue& out, std::string& code, std::string& err)
{
    std::string uri;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, e.model_id, uri, err));
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 17);
    UniValue params(UniValue::VARR);
    params.push_back(uri);
    params.push_back(HexStr(Span{secret, 32}));
    params.push_back(100000);
    return Rpc(cat, "createmodelrelease", params, out, code, err);
}

/** Make EnsureEconomy reload `cat`'s helper state from disk: it reloads only
 *  when the helper dir changes, so touch a second catalog first. */
void ForceEconomyReload(modelnet::ModelCatalog& cat, const fs::path& other_root)
{
    modelnet::ModelCatalog other{other_root, 8 << 20};
    const auto e = ImportTiny(other);
    UniValue out;
    std::string code, err;
    UniValue p(UniValue::VARR);
    p.push_back(e.model_id.Hex());
    BOOST_REQUIRE_MESSAGE(Rpc(other, "getmodeleconomyentry", p, out, code, err), err);
    (void)cat;
}

int CampaignsKnown(modelnet::ModelCatalog& cat)
{
    UniValue out;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeedstatus", UniValue(UniValue::VARR), out, code, err), code << " " << err);
    return out["campaigns_known"].getInt<int>();
}

/** `n` signed search records for one model, as its publisher re-signs it:
 *  sequence 1..n, each naming a new release_id. Returns importmodelindex's
 *  "imported" count; `last_release` is the newest release_id. */
int ImportReissuedRecords(modelnet::ModelCatalog& cat, const modelnet::Digest48& model, const modelnet::Digest48& artifact,
                          int n, std::string& last_release)
{
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch()).count();
    UniValue recs(UniValue::VARR);
    for (int i = 1; i <= n; ++i) {
        modelnet::ModelSearchRecord r;
        r.model_id = model;
        r.artifact_id = artifact;
        r.canonical_name = "reissued";
        r.display_name = "reissued";
        r.metadata_sequence = static_cast<uint64_t>(i);
        r.release_id = last_release = RandHex48();
        r.release_state = "FUNDING";
        r.release_target_atoms = 1000;
        r.expires_at = now_ms + 3'600'000;
        r.pubkey = pk;
        BOOST_REQUIRE_MESSAGE(modelnet::SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err), err);
        recs.push_back(modelnet::SearchRecordToJson(r));
    }
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("records", recs);
    UniValue ip(UniValue::VARR);
    ip.push_back(arg);
    UniValue out;
    std::string code;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "importmodelindex", ip, out, code, err), code << " " << err);
    return out["imported"].getInt<int>();
}

} // namespace

// Funding changes of a release reach the model event journal at the feed's
// granularity (per 5 % of the target, frozen and disclosed). Every change after
// the first used to share one dedupe key, so the journal dropped them.
BOOST_AUTO_TEST_CASE(release_funding_changes_reach_the_event_journal)
{
    const fs::path tmp = m_path_root / "release-funding-events";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    modelnet::BindModelEventLayer(tmp / "events", 1000);
    const auto model = ImportTiny(cat);
    // A release with a target of 100000 atoms: the feed notes a change every 5000.
    std::string uri, code, err;
    BOOST_REQUIRE(modelnet::EncodeResource(modelnet::ResourceKind::MODEL, model.model_id, uri, err));
    unsigned char secret[32];
    for (int i = 0; i < 32; ++i) secret[i] = static_cast<unsigned char>(i + 41);
    UniValue release_params(UniValue::VARR);
    release_params.push_back(uri);
    release_params.push_back(HexStr(Span{secret, 32}));
    release_params.push_back(100000);
    release_params.push_back(100000);
    UniValue created;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "createmodelrelease", release_params, created, code, err), code << " " << err);
    const std::string release = created["release_id"].get_str();
    const auto changes = [&] {
        UniValue p(UniValue::VOBJ);
        p.pushKV("cursor", "0");
        UniValue params(UniValue::VARR);
        params.push_back(p);
        UniValue out;
        BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelevents", params, out, code, err), code << " " << err);
        int n{0};
        for (const UniValue& ev : out["events"].getValues()) {
            if (ev["event_type"].get_str() == "RELEASE_FUNDING_CHANGED" && ev.exists("release_id") &&
                ev["release_id"].get_str() == release) {
                ++n;
            }
        }
        return n;
    };
    const auto pledge = [&](int64_t atoms) {
        UniValue params(UniValue::VARR);
        params.push_back(release);
        params.push_back(atoms);
        UniValue out;
        BOOST_REQUIRE_MESSAGE(Rpc(cat, "pledgemodelrelease", params, out, code, err), code << " " << err);
    };
    const int64_t step = 5000;
    pledge(step);
    BOOST_CHECK_EQUAL(changes(), 1);
    pledge(step);
    BOOST_CHECK_EQUAL(changes(), 2);
    pledge(1);
    BOOST_CHECK_EQUAL(changes(), 2);
    pledge(step - 1);
    BOOST_CHECK_EQUAL(changes(), 3);
}

// The journal key of a funding step comes from the feed's id for the step, not
// from the feed sequence: a restart can hand out a feed sequence again before
// feed.json is saved. Creating a campaign keeps the key of its published record.
BOOST_AUTO_TEST_CASE(release_funding_steps_keep_their_journal_key)
{
    const fs::path tmp = m_path_root / "release-funding-keys";
    modelnet::BindModelEventLayer(tmp / "events", 1000);
    modelnet::Digest48 model;
    model.data[0] = 0x71;
    const std::string release = RandHex48();
    std::string err;
    const auto step = [&](const std::string& extra, uint64_t feed_sequence) {
        modelnet::FeedEvent fe;
        fe.event_type = modelnet::FeedEventType::RELEASE_FUNDING_CHANGED;
        fe.model_id = model;
        fe.release_id = release;
        fe.event_id = modelnet::MakeFeedEventId(fe.event_type, model, release, 0, extra);
        fe.sequence = feed_sequence;
        modelnet::ObserveResult r;
        BOOST_REQUIRE_MESSAGE(modelnet::JournalObserveFeed(fe, r, err), err);
        return r.duplicate;
    };
    // Step 1 under feed sequence 7; after a restart, step 2 gets feed sequence 7 again.
    BOOST_CHECK(!step("001", 7));
    BOOST_CHECK_MESSAGE(!step("002", 7), "a new funding step was dropped as a duplicate");
    // The same step noted again under another feed sequence is a repeat.
    BOOST_CHECK(step("002", 9));

    // createmodelrelease journals the campaign without a record; publishing its
    // record (sequence 1) later is the same event.
    modelnet::FeedEvent created;
    created.event_type = modelnet::FeedEventType::RELEASE_CAMPAIGN_CREATED;
    created.model_id = model;
    created.release_id = release;
    modelnet::ObserveResult first, second;
    BOOST_REQUIRE_MESSAGE(modelnet::JournalObserveFeed(created, first, err), err);
    BOOST_CHECK(!first.duplicate);
    modelnet::ModelSearchRecord rec;
    rec.model_id = model;
    rec.release_id = release;
    rec.metadata_sequence = 1;
    BOOST_REQUIRE_MESSAGE(modelnet::JournalObserveSearchRecord(rec, second, err), err);
    BOOST_CHECK_MESSAGE(second.duplicate, "campaign creation journalled twice");
}

// W1. A search record from any peer can name a public model's artifact_id as
// part of a "release campaign". The v0.34.14 gate then refuses to serve that
// public model's plaintext. Here the record arrives through importmodelindex;
// searchmodels ingests peer replies through the same Put + AfterIndexPut path.
BOOST_AUTO_TEST_CASE(forged_campaign_record_does_not_stop_public_serving)
{
    const fs::path tmp = m_path_root / "w1-forged-campaign";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    std::string code, err;
    UniValue out;
    UniValue p(UniValue::VARR);
    p.push_back(pub.model_id.Hex());
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodeleconomyentry", p, out, code, err), err);
    BOOST_TEST_MESSAGE("before: downloadable_now=" << out["downloadable_now"].write());

    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w1-peer-a", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, gj), 200);

    // The forged record: unsigned, a fresh model_id, the victim's artifact_id,
    // and an invented release_id. No key, no funding, no signature.
    UniValue rec(UniValue::VOBJ);
    rec.pushKV("type", "btx-model-search-v1");
    rec.pushKV("model_id", RandHex48());
    rec.pushKV("artifact_id", pub.artifact_id.Hex());
    rec.pushKV("display_name", "bait");
    rec.pushKV("release_id", RandHex48());
    UniValue recs(UniValue::VARR);
    recs.push_back(rec);
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("records", recs);
    UniValue ip(UniValue::VARR);
    ip.push_back(arg);
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "importmodelindex", ip, out, code, err), err);
    BOOST_TEST_MESSAGE("importmodelindex: " << out.write());
    // Since af9020cd, importmodelindex verifies every record and refuses an
    // unsigned one, so the forged record never reaches the index. The
    // serving check below must still hold.
    BOOST_CHECK_EQUAL(out["imported"].getInt<int>(), 0);

    UniValue gj2;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w1-peer-b", gj2), 200);
    std::string body;
    const int st = GetPiece0(cat, pub, gj2, &body);
    BOOST_TEST_MESSAGE("after forged record: piece status " << st << " " << body.substr(0, 120));
    BOOST_CHECK_MESSAGE(st == 200, "a forged, unsigned campaign record stopped this node serving a public model (HTTP " << st << ")");
    modelnet::CatalogEntry after;
    BOOST_REQUIRE(cat.Find(pub.model_id, after));
    BOOST_TEST_MESSAGE("seeded after: " << after.seeded);
}

// W2. grant_redeems.json is rewritten in place (truncate, then write). A
// short write (crash, full disk) leaves invalid JSON, and every later free
// grant redemption fails closed until an operator deletes the file.
BOOST_AUTO_TEST_CASE(truncated_grant_store_does_not_wedge_free_serving)
{
    const fs::path tmp = m_path_root / "w2-grant-store";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w2-a", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, gj), 200);
    const fs::path store = FindFile(tmp, "grant_redeems.json");
    BOOST_REQUIRE(!store.empty());
    std::string raw;
    {
        std::ifstream in(store);
        raw.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    {
        std::ofstream out(store, std::ios::trunc);
        out << raw.substr(0, raw.size() / 2);
    }
    int ok = 0;
    std::string last;
    for (int i = 0; i < 5; ++i) {
        UniValue g;
        BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w2-b" + std::to_string(i), g), 200);
        if (GetPiece0(cat, pub, g, &last) == 200) ++ok;
    }
    BOOST_TEST_MESSAGE("after truncation: " << ok << "/5 fresh grants served; last body " << last.substr(0, 120));
    BOOST_CHECK_MESSAGE(ok == 5, "a truncated grant_redeems.json refuses every fresh free grant");
}

// Measurement: grant_redeems.json is never pruned and is read, parsed and
// rewritten whole on every redeemed piece.
BOOST_AUTO_TEST_CASE(grant_store_growth_measurement)
{
    const fs::path tmp = m_path_root / "w3-grant-growth";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w3-0", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, gj), 200);
    const fs::path store = FindFile(tmp, "grant_redeems.json");
    BOOST_REQUIRE(!store.empty());
    const auto s0 = fs::file_size(store);
    const int k = 40;
    for (int i = 1; i <= k; ++i) {
        UniValue g;
        BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w3-" + std::to_string(i), g), 200);
        BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, g), 200);
    }
    const auto s1 = fs::file_size(store);
    BOOST_TEST_MESSAGE("GROWTH " << k << " one-piece downloads added " << (s1 - s0) << " bytes ("
                       << double(s1 - s0) / k << " bytes per redeemed grant)");
    // Pre-load the store with history (as a long-running node accumulates)
    // and time one redemption.
    for (int entries : {10'000, 100'000}) {
        UniValue root;
        {
            std::ifstream in(store);
            std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            BOOST_REQUIRE(root.read(raw));
        }
        UniValue uses = root["uses"];
        UniValue bytes = root["redeemed_bytes"];
        for (int i = 0; i < entries; ++i) {
            const std::string n = strprintf("%064x", 0x77000000 + i);
            UniValue arr(UniValue::VARR);
            arr.push_back("f0:p0");
            uses.pushKV(n, arr);
            bytes.pushKV(n, 10);
        }
        root.pushKV("uses", uses);
        root.pushKV("redeemed_bytes", bytes);
        {
            std::ofstream out(store, std::ios::trunc);
            out << root.write() << "\n";
        }
        UniValue g;
        BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w3-big-" + std::to_string(entries), g), 200);
        const auto t0 = SteadyClock::now();
        BOOST_CHECK_EQUAL(GetPiece0(cat, pub, g), 200);
        const auto t1 = SteadyClock::now();
        BOOST_TEST_MESSAGE("GROWTH store with ~" << entries << " extra nonces (" << fs::file_size(store)
                           << " bytes): one piece GET took "
                           << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count() << " ms");
    }
}

// Every economy and feed RPC feeds the whole search index into the feed again.
// That is the helper re-reading its own index, not another peer relaying a
// record, so it must not raise sources_observed (which TRENDING sorts on).
BOOST_AUTO_TEST_CASE(feed_rereads_do_not_count_as_sources)
{
    const fs::path tmp = m_path_root / "feed-rereads";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    std::string code, err;
    UniValue status;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeedstatus", UniValue(UniValue::VARR), status, code, err), code << " " << err);
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch()).count();
    UniValue recs(UniValue::VARR);
    for (int i = 0; i < 3; ++i) {
        modelnet::ModelSearchRecord r;
        r.model_id.data[0] = static_cast<unsigned char>(0x50 + i);
        r.artifact_id.data[0] = static_cast<unsigned char>(0x58 + i);
        r.canonical_name = "reread " + std::to_string(i);
        r.display_name = r.canonical_name;
        r.published_at = now_ms - 1000 * (3 - i);
        r.expires_at = now_ms + 3'600'000;
        r.pubkey = pk;
        BOOST_REQUIRE_MESSAGE(modelnet::SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err), err);
        recs.push_back(modelnet::SearchRecordToJson(r));
    }
    UniValue import(UniValue::VOBJ);
    import.pushKV("records", recs);
    UniValue ip(UniValue::VARR);
    ip.push_back(import);
    UniValue out;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "importmodelindex", ip, out, code, err), code << " " << err);

    UniValue q(UniValue::VOBJ);
    q.pushKV("scope", "LOCAL");
    q.pushKV("mode", "TRENDING");
    UniValue fp(UniValue::VARR);
    fp.push_back(q);
    UniValue feed;
    for (int poll = 0; poll < 5; ++poll) {
        BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeed", fp, feed, code, err), code << " " << err);
        BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeedstatus", UniValue(UniValue::VARR), status, code, err), code << " " << err);
    }
    int models{0};
    for (const UniValue& item : feed["items"].getValues()) {
        if (item["event_type"].get_str() != "MODEL_PUBLISHED") continue;
        ++models;
        BOOST_CHECK_EQUAL(item["provenance"]["sources_observed"].getInt<int>(), 1);
    }
    BOOST_CHECK_EQUAL(models, 3);
}

// A re-read keeps a record the feed holds current without counting a source, so
// a record that stays in the index does not expire from the feed and come back
// as a new event (new sequence, first_seen_at and sources_observed).
BOOST_AUTO_TEST_CASE(feed_reread_keeps_a_held_record_current)
{
    modelnet::FeedStore feed;
    feed.SetTtlMs(1000);
    modelnet::ModelSearchRecord r;
    r.model_id.data[0] = 0x52;
    r.canonical_name = "held in the index";
    BOOST_REQUIRE(feed.NoteSearchRecord(r, 1000));
    const uint64_t noted = feed.Sequence();
    BOOST_REQUIRE(feed.RefreshSearchRecord(r, 1900));
    // More than the TTL after the record was noted, less after it was re-read.
    feed.Expire(2500);
    BOOST_CHECK_EQUAL(feed.Size(), 1U);
    BOOST_REQUIRE(feed.RefreshSearchRecord(r, 2600));
    BOOST_CHECK_EQUAL(feed.Sequence(), noted);
}

// A record that is no longer re-read (it left the index, for example through a
// tombstone) still expires when only the re-read writes to the feed.
BOOST_AUTO_TEST_CASE(feed_reread_still_expires_records_that_left_the_index)
{
    modelnet::FeedStore feed;
    feed.SetTtlMs(1000);
    modelnet::ModelSearchRecord gone, held;
    gone.model_id.data[0] = 0x53;
    gone.canonical_name = "left the index";
    held.model_id.data[0] = 0x54;
    held.canonical_name = "still in the index";
    BOOST_REQUIRE(feed.NoteSearchRecord(gone, 1000));
    BOOST_REQUIRE(feed.NoteSearchRecord(held, 1000));
    const uint64_t noted = feed.Sequence();
    BOOST_REQUIRE(feed.RefreshSearchRecord(held, 1800));
    BOOST_REQUIRE(feed.RefreshSearchRecord(held, 2500));
    BOOST_CHECK_EQUAL(feed.Size(), 1U);
    BOOST_CHECK_EQUAL(feed.Sequence(), noted);
}

// W3. The uses of an expired grant are never dropped. An expired grant cannot
// verify again, so keeping them only grows the file every piece GET rewrites.
BOOST_AUTO_TEST_CASE(expired_grant_uses_are_pruned)
{
    const fs::path tmp = m_path_root / "w3-grant-prune";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w3p-a", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, gj), 200);
    const fs::path store = FindFile(tmp, "grant_redeems.json");
    BOOST_REQUIRE(!store.empty());
    UniValue root;
    {
        std::ifstream in(store);
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_REQUIRE(root.read(raw));
    }
    // A grant that expired an hour ago (its expiry recorded the way the store
    // records it, when the store records it at all).
    const std::string old_nonce(64, 'd');
    UniValue uses = root["uses"];
    UniValue arr(UniValue::VARR);
    arr.push_back("f0:p0");
    uses.pushKV(old_nonce, arr);
    root.pushKV("uses", uses);
    UniValue exp = root.exists("expires_at") ? root["expires_at"] : UniValue(UniValue::VOBJ);
    exp.pushKV(old_nonce, static_cast<int64_t>(std::time(nullptr)) - 3600);
    root.pushKV("expires_at", exp);
    {
        std::ofstream out(store, std::ios::trunc);
        out << root.write() << "\n";
    }
    UniValue g2;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w3p-b", g2), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, pub, g2), 200);
    UniValue after;
    {
        std::ifstream in(store);
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_REQUIRE(after.read(raw));
    }
    BOOST_CHECK_MESSAGE(!after["uses"].exists(old_nonce), "uses of a grant that expired an hour ago are still kept");
}



// W1 fix, damaged state. The fix keeps the ids of releases this node created
// in local_releases.json. If that file exists but cannot be parsed, the gate
// must fail closed (withhold the plaintext of every campaign) rather than load
// an empty set, which would serve a local release's plaintext while it is not
// downloadable.
BOOST_AUTO_TEST_CASE(damaged_local_releases_file_fails_closed)
{
    const fs::path tmp = m_path_root / "w1-damaged-local-releases";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto rel = ImportTiny(cat);
    UniValue out;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(CreateRelease(cat, rel, out, code, err), code << " " << err);
    std::string err2;
    BOOST_REQUIRE(cat.Seed(rel.model_id, true, err2));
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, rel, "w1d-a", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, rel, gj), 404); // sanity: the release is gated

    const fs::path lr = FindFile(tmp, "local_releases.json");
    BOOST_REQUIRE(!lr.empty());
    std::string raw;
    {
        std::ifstream in(lr);
        raw.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    const std::string damaged = raw.substr(0, raw.size() / 2);
    {
        std::ofstream o(lr, std::ios::trunc);
        o << damaged;
    }
    ForceEconomyReload(cat, m_path_root / "w1-damaged-other");

    BOOST_REQUIRE(cat.Seed(rel.model_id, true, err2));
    UniValue gj2;
    BOOST_REQUIRE_EQUAL(Grant(cat, rel, "w1d-b", gj2), 200);
    std::string body;
    const int st = GetPiece0(cat, rel, gj2, &body);
    BOOST_TEST_MESSAGE("damaged local_releases.json: piece status " << st << " " << body.substr(0, 120));
    BOOST_CHECK_MESSAGE(st == 404, "a damaged local_releases.json served a local release's plaintext while not downloadable (HTTP " << st << ")");

    // The damaged file is kept for the operator, not overwritten.
    std::string now;
    {
        std::ifstream in(lr);
        now.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    BOOST_CHECK(now == damaged);
}

// W1 fix, write failure. If the local-release marker cannot be saved, the
// release must not be created: otherwise it is gated until the next restart
// and served afterwards.
BOOST_AUTO_TEST_CASE(local_release_marker_write_failure_refuses_release)
{
    const fs::path tmp = m_path_root / "w1-marker-write-failure";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto rel = ImportTiny(cat);
    // A directory where the temporary file must go makes every save fail.
    fs::create_directories(HelperDirOf(cat) / "local_releases.json.tmp");
    fs::remove(HelperDirOf(cat) / "local_releases.json");
    UniValue out;
    std::string code, err;
    const bool ok = CreateRelease(cat, rel, out, code, err);
    BOOST_TEST_MESSAGE("createmodelrelease with an unwritable marker: ok=" << ok << " code=" << code << " err=" << err);
    BOOST_CHECK_MESSAGE(!ok, "createmodelrelease succeeded although the local-release marker could not be saved");
}

// W2, issuance side. grant_nonces.json (read on every grant issue) had the same
// in-place write. A store already damaged by an older build must not refuse
// every later grant issue.
BOOST_AUTO_TEST_CASE(truncated_grant_nonce_store_does_not_wedge_issuance)
{
    const fs::path tmp = m_path_root / "w2-nonce-store";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "w2n-a", gj), 200);
    const fs::path store = FindFile(tmp, "grant_nonces.json");
    BOOST_REQUIRE(!store.empty());
    std::string raw;
    {
        std::ifstream in(store);
        raw.assign((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    }
    {
        std::ofstream out(store, std::ios::trunc);
        out << raw.substr(0, raw.size() / 2);
    }
    int issued = 0, served = 0;
    for (int i = 0; i < 5; ++i) {
        UniValue g;
        if (Grant(cat, pub, "w2n-b" + std::to_string(i), g) == 200) {
            ++issued;
            if (GetPiece0(cat, pub, g) == 200) ++served;
        }
    }
    BOOST_TEST_MESSAGE("after nonce-store truncation: " << issued << "/5 grants issued, " << served << " served");
    BOOST_CHECK_MESSAGE(issued == 5 && served == 5, "a truncated grant_nonces.json refuses every later grant issue");
    BOOST_CHECK(fs::exists(fs::PathFromString(fs::PathToString(store) + ".quarantine")));
}

// getmodeldirectory and getmodeldirectoryentry describe the local copy of a
// model the way searchmodels does: known, downloaded, seeded, pinned, partial.
BOOST_AUTO_TEST_CASE(directory_shows_the_local_copy_like_search)
{
    const fs::path tmp = m_path_root / "directory-local";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto model = ImportTiny(cat);
    std::string code, err;
    UniValue sq(UniValue::VOBJ);
    sq.pushKV("scope", "LOCAL");
    UniValue sp(UniValue::VARR);
    sp.push_back(sq);
    UniValue search;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "searchmodels", sp, search, code, err), code << " " << err);
    UniValue from_search;
    for (const UniValue& card : search["results"].getValues()) {
        if (card["model_id"].get_str() == model.model_id.Hex()) from_search = card["local"];
    }
    BOOST_REQUIRE(from_search.isObject());
    BOOST_REQUIRE(from_search["known"].get_bool());
    BOOST_REQUIRE(from_search["downloaded"].get_bool());

    UniValue ep(UniValue::VARR);
    ep.push_back(model.model_id.Hex());
    UniValue entry;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodeldirectoryentry", ep, entry, code, err), code << " " << err);
    BOOST_CHECK_EQUAL(entry["local"].write(), from_search.write());

    UniValue directory;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodeldirectory", UniValue(UniValue::VARR), directory, code, err), code << " " << err);
    bool listed{false};
    for (const UniValue& card : directory["results"].getValues()) {
        if (card["model_id"].get_str() != model.model_id.Hex()) continue;
        listed = true;
        BOOST_CHECK_EQUAL(card["local"].write(), from_search.write());
    }
    BOOST_CHECK(listed);

    // The economy lists that go through the same entries (getnewmodels here) report
    // the local copy too, so their pinned filter matches it.
    UniValue filters(UniValue::VOBJ);
    filters.pushKV("pinned", true);
    UniValue nq(UniValue::VOBJ);
    nq.pushKV("scope", "LOCAL");
    nq.pushKV("filters", filters);
    UniValue np(UniValue::VARR);
    np.push_back(nq);
    UniValue fresh;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getnewmodels", np, fresh, code, err), code << " " << err);
    bool fresh_listed{false};
    for (const UniValue& card : fresh["results"].getValues()) {
        if (card["model_id"].get_str() != model.model_id.Hex()) continue;
        fresh_listed = true;
        BOOST_CHECK_EQUAL(card["local"].write(), from_search.write());
    }
    BOOST_CHECK_MESSAGE(fresh_listed, "getnewmodels with pinned does not list the local model");
}

// A publisher may re-sign its search record for the same model with a higher
// sequence and a new release_id. The index takes each one (same model, so no
// new slot and no publisher quota). The campaign learned from the older record
// must go with it, or every re-signed record adds a campaign that nothing
// removes. Records arrive here through importmodelindex; searchmodels and the
// network feed ingest peer replies through the same Put + AfterIndexPut path.
BOOST_AUTO_TEST_CASE(reissued_release_records_do_not_grow_campaign_index)
{
    const fs::path tmp = m_path_root / "campaign-reissue";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto pub = ImportTiny(cat);
    const int before = CampaignsKnown(cat);
    modelnet::Digest48 model;
    std::string err;
    BOOST_REQUIRE(modelnet::Digest48::FromHex(RandHex48(), model, err));
    constexpr int N{40};
    std::string last_release;
    BOOST_REQUIRE_EQUAL(ImportReissuedRecords(cat, model, model, N, last_release), N);
    const int after = CampaignsKnown(cat);
    BOOST_TEST_MESSAGE("campaigns_known " << before << " -> " << after << " after " << N << " re-signed records for one model");
    BOOST_CHECK_EQUAL(after - before, 1);

    // The current release is still known.
    UniValue p(UniValue::VARR);
    p.push_back(last_release);
    UniValue out;
    std::string code;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelreleaseeconomics", p, out, code, err), code << " " << err);
    BOOST_CHECK(out.write().find(last_release) != std::string::npos);

    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, pub, "reissue-a", gj), 200);
    BOOST_CHECK_EQUAL(GetPiece0(cat, pub, gj), 200);
}

// The same re-signed records, for a model this node released: its own
// campaign is never dropped, and its plaintext stays withheld.
BOOST_AUTO_TEST_CASE(local_release_survives_reissued_records)
{
    const fs::path tmp = m_path_root / "campaign-reissue-local";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    const auto rel = ImportTiny(cat);
    UniValue out;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(CreateRelease(cat, rel, out, code, err), code << " " << err);
    BOOST_REQUIRE(cat.Seed(rel.model_id, true, err));
    UniValue gj;
    BOOST_REQUIRE_EQUAL(Grant(cat, rel, "reissue-local-a", gj), 200);
    BOOST_REQUIRE_EQUAL(GetPiece0(cat, rel, gj), 404); // sanity: the release is gated
    const int before = CampaignsKnown(cat);

    constexpr int N{20};
    std::string last_release;
    const int imported = ImportReissuedRecords(cat, rel.model_id, rel.artifact_id, N, last_release);
    const int after = CampaignsKnown(cat);
    BOOST_TEST_MESSAGE("imported " << imported << "/" << N << "; campaigns_known " << before << " -> " << after);
    BOOST_CHECK_LE(after - before, 1);

    BOOST_REQUIRE(cat.Seed(rel.model_id, true, err));
    UniValue gj2;
    BOOST_REQUIRE_EQUAL(Grant(cat, rel, "reissue-local-b", gj2), 200);
    BOOST_CHECK_EQUAL(GetPiece0(cat, rel, gj2), 404);
}

// A feed filter drops a model's economy entry, but its feed item stayed. The
// page pairs items and entries by position, so the items after it showed the
// entry of another model, and the filtered model was still listed.
BOOST_AUTO_TEST_CASE(filtered_feed_keeps_each_entry_with_its_model)
{
    const fs::path tmp = m_path_root / "feed-filter-pairs";
    modelnet::ModelCatalog cat{tmp, 8 << 20};
    std::vector<unsigned char> pk, sk;
    std::string code, err;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                               std::chrono::system_clock::now().time_since_epoch()).count();
    // Bind the helper's feed and economy state to this catalog before importing.
    UniValue status;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeedstatus", UniValue(UniValue::VARR), status, code, err), code << " " << err);
    std::set<std::string> funding;
    UniValue recs(UniValue::VARR);
    for (int i = 0; i < 6; ++i) {
        modelnet::ModelSearchRecord r;
        r.model_id.data[0] = static_cast<unsigned char>(0x60 + i);
        r.artifact_id.data[0] = static_cast<unsigned char>(0x70 + i);
        r.canonical_name = "feed filter " + std::to_string(i);
        r.display_name = r.canonical_name;
        r.metadata_sequence = 1;
        r.published_at = now_ms - 1000 * (6 - i);
        if (i % 2 == 0) {
            // A model still in its funding campaign: not released.
            r.release_id = RandHex48();
            r.release_state = "FUNDING";
            r.release_target_atoms = 1000;
            funding.insert(r.model_id.Hex());
        }
        r.expires_at = now_ms + 3'600'000;
        r.pubkey = pk;
        BOOST_REQUIRE_MESSAGE(modelnet::SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err), err);
        recs.push_back(modelnet::SearchRecordToJson(r));
    }
    UniValue import(UniValue::VOBJ);
    import.pushKV("records", recs);
    UniValue ip(UniValue::VARR);
    ip.push_back(import);
    UniValue out;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "importmodelindex", ip, out, code, err), code << " " << err);

    UniValue filters(UniValue::VOBJ);
    filters.pushKV("released_only", true);
    UniValue q(UniValue::VOBJ);
    q.pushKV("scope", "LOCAL");
    q.pushKV("mode", "NEWEST");
    q.pushKV("limit", 50);
    q.pushKV("filters", filters);
    UniValue fp(UniValue::VARR);
    fp.push_back(q);
    UniValue feed;
    BOOST_REQUIRE_MESSAGE(Rpc(cat, "getmodelfeed", fp, feed, code, err), code << " " << err);
    BOOST_REQUIRE(feed["items"].isArray());
    BOOST_CHECK(!feed["items"].empty());
    for (const UniValue& item : feed["items"].getValues()) {
        const std::string id = item["model_id"].get_str();
        BOOST_CHECK_MESSAGE(!funding.count(id), "a model the filter excludes is listed: " << id);
        BOOST_REQUIRE_MESSAGE(item.exists("entry"), "item without its entry: " << id);
        BOOST_CHECK_EQUAL(item["entry"]["model_id"].get_str(), id);
    }
}

BOOST_AUTO_TEST_SUITE_END()
