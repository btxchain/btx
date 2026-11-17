// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/catalog.h>
#include <modelnet/feed.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/protocol.h>
#include <modelnet/records.h>
#include <modelnet/search.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#ifndef WIN32
#include <csignal>
#include <sys/resource.h>
#include <unistd.h>
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_store_write_tests, BasicTestingSetup)

#ifndef WIN32
namespace {
std::string ReadAll(const fs::path& p)
{
    std::ifstream in(p, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

//! Run fn with RLIMIT_FSIZE set to limit, as a full disk would cut a write
//! short. SIGXFSZ is ignored so the write fails with EFBIG instead.
template <typename Fn>
bool CutShort(uint64_t limit, Fn&& fn)
{
    struct rlimit old_limit {};
    BOOST_REQUIRE(::getrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    struct rlimit cut{old_limit};
    cut.rlim_cur = limit;
    const auto old_handler{std::signal(SIGXFSZ, SIG_IGN)};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &cut) == 0);
    const bool ok{fn()};
    BOOST_REQUIRE(::setrlimit(RLIMIT_FSIZE, &old_limit) == 0);
    std::signal(SIGXFSZ, old_handler);
    return ok;
}
} // namespace

BOOST_AUTO_TEST_CASE(helper_json_store_cut_short_keeps_the_old_file)
{
    // The helper keeps local stores (acl.json, identities.json, records.json,
    // community.json, ...) as JSON files that it reads, changes and writes
    // back. A write that is cut short must fail and leave the old file.
    const fs::path dir = m_path_root / "helper-json-cut-short";
    modelnet::ModelCatalog cat{dir, 8 << 20};
    const fs::path acl = dir / "acl.json";
    UniValue result;
    std::string code, err;
    const auto call = [&](const std::string& method, const UniValue& params) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", params);
        result = UniValue(UniValue::VOBJ);
        code.clear();
        err.clear();
        return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    };
    const auto rule = [](const std::string& name) {
        UniValue r(UniValue::VOBJ);
        r.pushKV("name", name);
        r.pushKV("action", "deny");
        UniValue params(UniValue::VARR);
        params.push_back(r);
        return params;
    };

    BOOST_REQUIRE_MESSAGE(call("setmodelrule", rule("first")), err);
    const std::string before = ReadAll(acl);
    BOOST_REQUIRE_GT(before.size(), 1U);

    // The new file is larger than the old one, so the write is cut short.
    BOOST_CHECK_MESSAGE(!CutShort(before.size(), [&] { return call("setmodelrule", rule("second")); }),
                        "setmodelrule reported a rule as saved although acl.json was cut short");
    BOOST_CHECK_EQUAL(code, "IO");
    BOOST_CHECK_EQUAL(ReadAll(acl), before);
    BOOST_CHECK(!fs::exists(dir / "acl.json.tmp"));
    BOOST_REQUIRE_MESSAGE(call("listmodelrules", UniValue(UniValue::VARR)), err);
    BOOST_CHECK_MESSAGE(result["rules"].isArray() && result["rules"].size() == 1 &&
                            result["rules"][0]["name"].get_str() == "first",
                        "acl.json lost its rules: " + result.write());

    // A write that is not cut short still replaces the file.
    BOOST_REQUIRE_MESSAGE(call("setmodelrule", rule("second")), err);
    BOOST_REQUIRE_MESSAGE(call("listmodelrules", UniValue(UniValue::VARR)), err);
    BOOST_CHECK(result["rules"].isArray() && result["rules"].size() == 2);
    BOOST_CHECK(!fs::exists(dir / "acl.json.tmp"));

    // identities.json: a cut-short write used to drop every listed identity
    // at the next read.
    const fs::path ids = dir / "identities.json";
    UniValue label(UniValue::VARR);
    label.push_back("first");
    BOOST_REQUIRE_MESSAGE(call("createmodelidentity", label), err);
    const std::string first_id = result["id"].get_str();
    const std::string ids_before = ReadAll(ids);
    BOOST_REQUIRE_GT(ids_before.size(), 1U);
    label = UniValue(UniValue::VARR);
    label.push_back("second");
    BOOST_CHECK_MESSAGE(!CutShort(ids_before.size(), [&] { return call("createmodelidentity", label); }),
                        "createmodelidentity reported an identity as saved although identities.json was cut short");
    BOOST_CHECK_EQUAL(code, "IO");
    BOOST_CHECK_EQUAL(ReadAll(ids), ids_before);
    BOOST_REQUIRE_MESSAGE(call("listmodelidentities", UniValue(UniValue::VARR)), err);
    BOOST_CHECK_MESSAGE(result["identities"].isArray() && result["identities"].size() == 1 &&
                            result["identities"][0]["id"].get_str() == first_id,
                        "identities.json lost its identities: " + result.write());
}

// A helper JSON store that is there but cannot be read (not parsable, or a
// regular file that cannot be opened) is kept: the calls that write it refuse
// instead of replacing it, as for the safety files and bounty-store.json.
BOOST_AUTO_TEST_CASE(unreadable_helper_stores_are_kept)
{
    const fs::path dir = m_path_root / "helper-unreadable-stores";
    modelnet::ModelCatalog cat{dir, 8 << 20};
    UniValue result;
    std::string code, err;
    const auto call = [&](const std::string& method, const UniValue& params) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", params);
        result = UniValue(UniValue::VOBJ);
        code.clear();
        err.clear();
        return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    };
    const auto one = [](const UniValue& v) {
        UniValue params(UniValue::VARR);
        params.push_back(v);
        return params;
    };
    const std::string garbage = "{\"entries\":[";
    const auto plant = [&](const std::string& name) {
        std::ofstream out(dir / fs::PathFromString(name), std::ios::binary | std::ios::trunc);
        out << garbage;
    };

    plant("identities.json");
    BOOST_CHECK(!call("createmodelidentity", one(UniValue("label"))));
    BOOST_CHECK_EQUAL(ReadAll(dir / "identities.json"), garbage);

    plant("acl.json");
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("name", "r");
    rule.pushKV("action", "deny");
    BOOST_CHECK(!call("setmodelrule", one(rule)));
    BOOST_CHECK_EQUAL(ReadAll(dir / "acl.json"), garbage);
    BOOST_CHECK(call("listmodelrules", UniValue(UniValue::VARR)));
    {
        std::ofstream out(dir / "acl.json", std::ios::binary | std::ios::trunc);
        out << "42";
    }
    BOOST_CHECK(!call("setmodelrule", one(rule)));
    BOOST_CHECK_EQUAL(ReadAll(dir / "acl.json"), "42");

    plant("community.json");
    BOOST_CHECK(!call("joinmodelcircle", one(UniValue("circle-1"))));
    BOOST_CHECK(!call("leavemodelcircle", one(UniValue("circle-1"))));
    BOOST_CHECK_EQUAL(ReadAll(dir / "community.json"), garbage);

    plant("mirror.json");
    UniValue sel(UniValue::VOBJ);
    sel.pushKV("query", "q");
    sel.pushKV("idempotency_key", "unreadable-mirror");
    BOOST_CHECK(!call("setmodelmirror", one(sel)));
    BOOST_CHECK_EQUAL(ReadAll(dir / "mirror.json"), garbage);

    // A regular file that cannot be opened counts as unreadable as well.
    if (::geteuid() != 0) {
        const std::string kept = "{\"circles\":[\"kept\"]}";
        {
            std::ofstream out(dir / "community.json", std::ios::binary | std::ios::trunc);
            out << kept;
        }
        fs::permissions(dir / "community.json", fs::perms::none);
        BOOST_CHECK(!call("joinmodelcircle", one(UniValue("circle-2"))));
        fs::permissions(dir / "community.json", fs::perms::owner_read | fs::perms::owner_write);
        BOOST_CHECK_EQUAL(ReadAll(dir / "community.json"), kept);
    }

    // records.json, the signed record cache, is kept too: a join issues a
    // signed record, which then stays in memory only.
    {
        std::ofstream out(dir / "community.json", std::ios::binary | std::ios::trunc);
        out << "{}";
    }
    plant("records.json");
    BOOST_CHECK_MESSAGE(call("joinmodelcircle", one(UniValue("circle-3"))), err);
    BOOST_CHECK_EQUAL(ReadAll(dir / "records.json"), garbage);

    // A peer's ServiceReceipt goes to receipts.json; an unreadable one is kept.
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(modelnet::GenerateMlDsa44(pk, sk, err));
    const auto receipt = [&](const std::string& transfer) {
        UniValue body(UniValue::VOBJ);
        modelnet::FillRecordCommon(body, 0, modelnet::ProviderId(pk), static_cast<int64_t>(std::time(nullptr)), 3600);
        body.pushKV("receipt_kind", 1);
        body.pushKV("transfer_id", transfer);
        body.pushKV("provider_id", modelnet::ProviderId(pk).Hex());
        body.pushKV("buyer_id", std::string(96, 'b'));
        body.pushKV("model_id", std::string(96, 'c'));
        body.pushKV("artifact_id", std::string(96, 'd'));
        body.pushKV("file_index", 0);
        body.pushKV("first_piece", 0);
        body.pushKV("piece_count", 1);
        body.pushKV("verified_bytes", 1);
        body.pushKV("outcome", 0);
        body.pushKV("previous_receipt_id", std::string(96, '0'));
        std::vector<unsigned char> payload, sig;
        modelnet::Digest48 rid;
        BOOST_REQUIRE_MESSAGE(modelnet::SignTypedRecord(modelnet::RECORD_SERVICE_RECEIPT, body, sk, payload, sig, rid, err), err);
        UniValue post(UniValue::VOBJ);
        post.pushKV("payload_hex", HexStr(payload));
        post.pushKV("sig_hex", HexStr(sig));
        post.pushKV("pubkey_hex", HexStr(pk));
        modelnet::NativeRequest req;
        req.method = "POST";
        req.path = std::string(modelnet::MODEL_HTTP_ROOT) + "ext/receipts";
        req.body = post.write();
        modelnet::NativeResponse resp;
        BOOST_REQUIRE(modelnet::HandleNativeRequest(cat, req, resp));
        return resp.status;
    };
    BOOST_REQUIRE_EQUAL(receipt(std::string(64, 'a')), 200);
    plant("receipts.json");
    BOOST_CHECK_EQUAL(receipt(std::string(64, 'e')), 500);
    BOOST_CHECK_EQUAL(ReadAll(dir / "receipts.json"), garbage);
}

BOOST_AUTO_TEST_CASE(catalog_write_cut_short_keeps_catalog_json)
{
    // ModelCatalog::PersistLocked writes catalog.json.tmp and renames it over
    // catalog.json. A temp file that was cut short must not be renamed over it.
    const fs::path dir = m_path_root / "catalog-cut-short";
    {
        modelnet::ModelCatalog cat{dir, 8 << 20};
        BOOST_REQUIRE(cat.AddPeer("127.0.0.1:10001"));
    }
    const fs::path file = dir / "catalog.json";
    const std::string before = ReadAll(file);
    BOOST_REQUIRE_GT(before.size(), 1U);
    {
        modelnet::ModelCatalog cat{dir, 8 << 20};
        CutShort(before.size(), [&] { return cat.AddPeer("127.0.0.1:10002"); });
    }
    BOOST_CHECK_EQUAL(ReadAll(file), before);
    BOOST_CHECK(!fs::exists(dir / "catalog.json.tmp"));
    modelnet::ModelCatalog reopened{dir, 8 << 20};
    const std::vector<std::string> peers = reopened.Peers();
    BOOST_CHECK_MESSAGE(std::find(peers.begin(), peers.end(), "127.0.0.1:10001") != peers.end(),
                        "catalog.json was replaced by a cut-short file and reopened without its peers");
}

BOOST_AUTO_TEST_CASE(feed_and_search_index_cut_short_keep_the_old_file)
{
    // feed.json and search-index.json are loaded when the helper starts; a
    // save that is cut short must fail and keep the previous file.
    using namespace modelnet;
    const fs::path feed_path = m_path_root / "feed-cut-short" / "feed.json";
    FeedStore feed;
    feed.SetPath(feed_path);
    ModelSearchRecord first;
    first.model_id.data[0] = 4;
    first.display_name = "First";
    first.canonical_name = "First";
    first.published_at = 50;
    BOOST_REQUIRE(feed.NoteSearchRecord(first, 10));
    std::string err;
    BOOST_REQUIRE(feed.Save(err));
    const std::string feed_before = ReadAll(feed_path);
    ModelSearchRecord second{first};
    second.model_id.data[0] = 5;
    second.display_name = "Second";
    second.canonical_name = "Second";
    BOOST_REQUIRE(feed.NoteSearchRecord(second, 11));
    BOOST_CHECK_MESSAGE(!CutShort(feed_before.size(), [&] { return feed.Save(err); }),
                        "FeedStore::Save reported a cut-short feed.json as saved");
    BOOST_CHECK_EQUAL(ReadAll(feed_path), feed_before);
    BOOST_CHECK(!fs::exists(fs::PathFromString(fs::PathToString(feed_path) + ".tmp")));
    FeedStore loaded;
    loaded.SetPath(feed_path);
    BOOST_CHECK(loaded.Load(20, err));
    FeedQuery q;
    std::string next;
    const auto items = loaded.Query(q, 20, next);
    BOOST_CHECK_MESSAGE(items.size() == 1 && items[0].rec.display_name == "First",
                        "feed.json lost its events: " + std::to_string(items.size()) + " loaded");

    const fs::path index_path = m_path_root / "index-cut-short" / "search-index.json";
    std::vector<unsigned char> pk, sk;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    const auto signed_record = [&](const std::string& name, unsigned char tag) {
        ModelSearchRecord r;
        r.model_id.data[0] = tag;
        r.artifact_id.data[0] = static_cast<unsigned char>(tag + 1);
        r.canonical_name = name;
        r.display_name = name;
        r.pubkey = pk;
        r.published_at = tag;
        r.expires_at = 1'000'000;
        r.description = name;
        r.short_description = name;
        r.object_kind = "MODEL";
        BOOST_REQUIRE(SignSearchRecord(r, Span<const unsigned char>{sk.data(), sk.size()}, err));
        return r;
    };
    SearchIndex idx;
    const auto rec_a = signed_record("Index A", 1);
    BOOST_REQUIRE_MESSAGE(idx.Put(rec_a, 10, err), err);
    BOOST_REQUIRE(idx.Save(index_path, err));
    const std::string index_before = ReadAll(index_path);
    BOOST_REQUIRE_MESSAGE(idx.Put(signed_record("Index B", 3), 11, err), err);
    BOOST_CHECK_MESSAGE(!CutShort(index_before.size(), [&] { return idx.Save(index_path, err); }),
                        "SearchIndex::Save reported a cut-short search-index.json as saved");
    BOOST_CHECK_EQUAL(ReadAll(index_path), index_before);
    SearchIndex reloaded;
    BOOST_CHECK(reloaded.Load(index_path, 20, err));
    BOOST_CHECK_MESSAGE(reloaded.Get(rec_a.model_id) != nullptr, "search-index.json lost its records");
}
#endif // WIN32

// createmodelidentity adds an identity to identities.json, which every new
// identity writes again whole and listmodelidentities returns: a label is at
// most 256 bytes.
BOOST_AUTO_TEST_CASE(model_identity_label_is_bounded)
{
    const fs::path dir = m_path_root / "identity-label-bound";
    modelnet::ModelCatalog cat{dir, 8 << 20};
    UniValue result;
    std::string code, err;
    const auto call = [&](const std::string& method, const UniValue& params) {
        UniValue rpc(UniValue::VOBJ);
        rpc.pushKV("method", method);
        rpc.pushKV("params", params);
        result = UniValue(UniValue::VOBJ);
        code.clear();
        err.clear();
        return modelnet::DispatchHelperRpc(cat, rpc, result, code, err);
    };
    const auto create = [&](const std::string& label) {
        UniValue params(UniValue::VARR);
        params.push_back(label);
        return call("createmodelidentity", params);
    };
    BOOST_REQUIRE_MESSAGE(create(std::string(256, 'l')), err);
    BOOST_CHECK(!create(std::string(257, 'l')));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");
    BOOST_REQUIRE_MESSAGE(call("listmodelidentities", UniValue(UniValue::VARR)), err);
    BOOST_CHECK_EQUAL(result["identities"].size(), 1U);
}

BOOST_AUTO_TEST_SUITE_END()
