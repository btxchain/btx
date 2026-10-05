// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// v0.34.14 re-review: free-grant single use (bca3ea11) and the new
// "undownloadable plaintext is not served" gate. Regtest/unit only.

#include <crypto/common.h>
#include <modelnet/catalog.h>
#include <modelnet/free_grant.h>
#include <modelnet/helper.h>
#include <modelnet/resource_uri.h>
#include <random.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <boost/test/unit_test.hpp>

#include <ctime>
#include <fstream>
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

} // namespace

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
    BOOST_CHECK_EQUAL(out["imported"].getInt<int>(), 1);

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

BOOST_AUTO_TEST_SUITE_END()
