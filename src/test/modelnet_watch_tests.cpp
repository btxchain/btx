// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/model_watch.h>
#include <modelnet/resource_uri.h>
#include <modelnet/subscription_mandate.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_watch_tests, BasicTestingSetup)

namespace {

modelnet::ModelEvent MakeSigned(const std::string& publisher, const std::string& oid,
                                 modelnet::ModelEventType t = modelnet::ModelEventType::MODEL_PUBLISHED)
{
    modelnet::ModelEvent e;
    e.event_type = t;
    e.object_id = oid;
    e.model_id = oid;
    e.publisher_id = publisher;
    e.verification_state = "SIGNED_OK";
    e.source = "SEARCH";
    e.record_sequence = 1;
    e.match.family = "qwen";
    e.match.architecture = "transformer";
    e.match.display_name = "Qwen";
    e.match.canonical_name = "Qwen";
    e.match.tags = {"gguf"};
    return e;
}

UniValue RpcParamsObj(const UniValue& o)
{
    UniValue p(UniValue::VARR);
    p.push_back(o);
    return p;
}

UniValue HelperReq(const std::string& method, const UniValue& arg)
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", arg.isArray() ? arg : RpcParamsObj(arg));
    return req;
}

std::string HexBytes(const std::vector<unsigned char>& b)
{
    return HexStr(Span<const unsigned char>{b.data(), b.size()});
}

UniValue ChannelRpcObj(const modelnet::SignedChannel& ch)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("publisher_id", ch.publisher_id);
    o.pushKV("name", ch.name);
    o.pushKV("channel", ch.channel);
    o.pushKV("target_uri", ch.target_uri);
    o.pushKV("sequence", static_cast<int64_t>(ch.sequence));
    o.pushKV("expiry", ch.expiry);
    if (!ch.pubkey.empty()) o.pushKV("pubkey", HexBytes(ch.pubkey));
    o.pushKV("signature", HexBytes(ch.sig));
    return o;
}

void AssertZeroSpendNoWallet(const UniValue& o)
{
    BOOST_REQUIRE(o.isObject());
    if (o.exists("automatic_spend_atoms")) {
        BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int>(), 0);
    }
    BOOST_CHECK(!o.exists("wallet"));
    BOOST_CHECK(!o.exists("wallet_key"));
    BOOST_CHECK(!o.exists("wallet_keys"));
    BOOST_CHECK(!o.exists("wallet_signed"));
    if (o.exists("spends")) BOOST_CHECK(!o["spends"].get_bool());
    if (o.exists("channels") && o["channels"].isArray()) {
        for (const auto& ch : o["channels"].getValues()) {
            if (ch.isObject()) AssertZeroSpendNoWallet(ch);
        }
    }
}

bool ListHasChannel(const UniValue& listed, const modelnet::SignedChannel& ch)
{
    if (!listed.exists("channels") || !listed["channels"].isArray()) return false;
    for (const auto& item : listed["channels"].getValues()) {
        if (!item.isObject()) continue;
        if (item["publisher_id"].get_str() == ch.publisher_id && item["name"].get_str() == ch.name &&
            item["channel"].get_str() == ch.channel && item["target_uri"].get_str() == ch.target_uri &&
            item["sequence"].getInt<int64_t>() == static_cast<int64_t>(ch.sequence)) {
            return true;
        }
    }
    return false;
}

UniValue WatchMandateJson(const std::string& mandate_id)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", 1);
    o.pushKV("mandate_id", mandate_id);
    o.pushKV("owner_identity", std::string(96, 'a'));
    o.pushKV("network_id", std::string(64, '0'));
    o.pushKV("publisher_id", std::string(96, 'b'));
    UniValue kinds(UniValue::VARR);
    kinds.push_back("MODEL");
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    o.pushKV("allowed_actions", acts);
    o.pushKV("per_action_principal_limit_atoms", "50");
    o.pushKV("total_principal_limit_atoms", "100");
    o.pushKV("total_fee_limit_atoms", "20");
    o.pushKV("outstanding_exposure_limit_atoms", "200");
    o.pushKV("max_actions", 16);
    o.pushKV("max_concurrent_reservations", 8);
    o.pushKV("expires_at_ms", "4000000000000");
    o.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    o.pushKV("minimum_confirmations", 1);
    o.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    o.pushKV("revocation_counter", "0");
    return o;
}

UniValue MandateRpcArr(const UniValue& o)
{
    UniValue a(UniValue::VARR);
    a.push_back(o);
    return a;
}

size_t CountFundActions(const std::vector<modelnet::QueuedWatchAction>& acts)
{
    size_t n = 0;
    for (const auto& a : acts) {
        BOOST_CHECK(!a.spends);
        if (a.action == modelnet::ActionPolicy::FUND_WITH_MANDATE) ++n;
    }
    return n;
}

} // namespace

BOOST_AUTO_TEST_CASE(watch_match_publisher_collection_model_query)
{
    using namespace modelnet;
    ModelWatch pub;
    pub.kind = WatchKind::PUBLISHER;
    pub.publisher_id = "pub-a";
    ModelWatch other;
    other.kind = WatchKind::PUBLISHER;
    other.publisher_id = "pub-b";
    ModelWatch model;
    model.kind = WatchKind::MODEL;
    model.model_id = "mid-1";
    ModelWatch coll;
    coll.kind = WatchKind::COLLECTION;
    coll.collection_id = "col-1";
    ModelWatch q;
    q.kind = WatchKind::QUERY;
    q.filters.family = "qwen";
    q.filters.tags = {"gguf"};

    ModelEvent ev = MakeSigned("pub-a", "mid-1");
    BOOST_CHECK(WatchMatchesEvent(pub, ev));
    BOOST_CHECK(!WatchMatchesEvent(other, ev));
    BOOST_CHECK(WatchMatchesEvent(model, ev));
    BOOST_CHECK(!WatchMatchesEvent(coll, ev));
    BOOST_CHECK(WatchMatchesEvent(q, ev));

    ModelEvent unsigned_ev = ev;
    unsigned_ev.verification_state = "UNVERIFIED";
    BOOST_CHECK(!WatchMatchesEvent(pub, unsigned_ev));
    BOOST_CHECK(!WatchMatchesEvent(model, unsigned_ev));

    ModelEvent coll_ev = MakeSigned("pub-a", "col-1", ModelEventType::COLLECTION_UPDATED);
    coll_ev.collection_id = "col-1";
    coll_ev.object_kind = "COLLECTION";
    BOOST_CHECK(WatchMatchesEvent(coll, coll_ev));

    ModelEvent llama = MakeSigned("pub-a", "mid-2");
    llama.match.family = "llama";
    BOOST_CHECK(!WatchMatchesEvent(q, llama));
}

BOOST_AUTO_TEST_CASE(watch_model_requires_verified_enough)
{
    using namespace modelnet;
    const std::string mid = "mid-watch-1";
    ModelWatch model;
    model.kind = WatchKind::MODEL;
    model.model_id = mid;
    model.action = ActionPolicy::FREE_DOWNLOAD;

    ModelEvent signed_ev = MakeSigned("pub-a", mid);
    BOOST_CHECK(WatchMatchesEvent(model, signed_ev));

    ModelEvent chain = signed_ev;
    chain.verification_state = "CHAIN_OBSERVED";
    BOOST_CHECK(WatchMatchesEvent(model, chain));

    // Unsigned / local-observed remote records matching the watched id (or
    // claiming a different object_id) must not fire the watch.
    ModelEvent unverified = signed_ev;
    unverified.verification_state = "UNVERIFIED";
    unverified.object_id = "attacker-nominated";
    BOOST_CHECK(!WatchMatchesEvent(model, unverified));

    ModelEvent local = signed_ev;
    local.verification_state = "LOCAL_OBSERVED";
    local.object_id = "attacker-nominated";
    BOOST_CHECK(!WatchMatchesEvent(model, local));

    ModelSearchRecord rec;
    rec.model_id.data[0] = 0xaa;
    rec.signed_ok = false;
    rec.object_kind = "MODEL";
    rec.btx_uri = "btx://attacker-nominated";
    ModelWatch rec_watch;
    rec_watch.kind = WatchKind::MODEL;
    rec_watch.model_id = rec.model_id.Hex();
    rec_watch.action = ActionPolicy::FREE_DOWNLOAD;
    BOOST_CHECK(!SearchRecordMatchesWatch(rec_watch, rec));
    rec.signed_ok = true;
    BOOST_CHECK(SearchRecordMatchesWatch(rec_watch, rec));

    ModelWatchStore store(m_path_root / "watch-model-verified");
    std::string err;
    BOOST_REQUIRE(store.PutWatch(model, err));
    store.NoteEvent(local);
    BOOST_CHECK(store.PeekActions().empty());
    store.NoteEvent(signed_ev);
    const auto acts = store.DrainActions();
    BOOST_REQUIRE_EQUAL(acts.size(), 1U);
    BOOST_CHECK_EQUAL(ActionPolicyName(acts[0].action), std::string("FREE_DOWNLOAD"));
    BOOST_CHECK(!acts[0].spends);
    BOOST_CHECK_EQUAL(acts[0].object_id, mid);
    const UniValue j = WatchActionToJson(acts[0]);
    BOOST_CHECK_EQUAL(j["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(j["getmodel_mode"].get_str(), "FREE_ONLY");
}

BOOST_AUTO_TEST_CASE(watch_free_download_queues_not_spend)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-actions";
    BindModelEventLayer(dir, 32);
    ModelWatch w;
    w.kind = WatchKind::PUBLISHER;
    w.publisher_id = "pub-a";
    w.action = ActionPolicy::FREE_DOWNLOAD;
    std::string err;
    BOOST_REQUIRE(BoundModelWatchStore()->PutWatch(w, err));
    ObserveResult o;
    BOOST_REQUIRE(JournalObserve(MakeSigned("pub-a", "mid-9"), o, err));
    const auto acts = BoundModelWatchStore()->DrainActions();
    BOOST_REQUIRE_EQUAL(acts.size(), 1U);
    BOOST_CHECK_EQUAL(ActionPolicyName(acts[0].action), std::string("FREE_DOWNLOAD"));
    BOOST_CHECK(acts[0].downloads);
    BOOST_CHECK(!acts[0].spends);
    BOOST_CHECK(!acts[0].job_id.empty());
    BOOST_CHECK_EQUAL(acts[0].object_id, "mid-9");
}

BOOST_AUTO_TEST_CASE(watch_persist_restart)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-persist";
    std::string wid;
    {
        ModelWatchStore s(dir);
        ModelWatch w;
        w.kind = WatchKind::MODEL;
        w.model_id = "abc";
        w.action = ActionPolicy::KEEP;
        std::string err;
        BOOST_REQUIRE(s.PutWatch(w, err));
        wid = w.watch_id;
        BOOST_CHECK(fs::exists(dir / "watches.json"));
    }
    ModelWatchStore s2(dir);
    ModelWatch got;
    BOOST_REQUIRE(s2.GetWatch(wid, got));
    BOOST_CHECK_EQUAL(got.model_id, "abc");
    BOOST_CHECK_EQUAL(ActionPolicyName(got.action), std::string("KEEP"));
}

BOOST_AUTO_TEST_CASE(watch_longpoll_timeout)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-longpoll";
    BindModelEventLayer(dir, 16);
    UniValue p(UniValue::VOBJ);
    p.pushKV("cursor", static_cast<int64_t>(BoundModelEventJournal()->Cursor()));
    p.pushKV("timeout_ms", 120);
    UniValue result;
    std::string code, err;
    const auto t0 = std::chrono::steady_clock::now();
    BOOST_REQUIRE(DispatchModelWatchRpc("waitformodelevent", RpcParamsObj(p), result, code, err, nullptr));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_CHECK(result["events"].isArray());
    BOOST_CHECK_EQUAL(result["events"].size(), 0U);
    BOOST_CHECK(result["timeout"].get_bool());
    BOOST_CHECK(!result["interrupted"].get_bool());
    BOOST_CHECK_GE(ms, 50);
    BOOST_CHECK_LT(ms, 2000);

    std::atomic<bool> stop{true};
    UniValue r2;
    BOOST_REQUIRE(DispatchModelWatchRpc("waitformodelevent", RpcParamsObj(p), r2, code, err, &stop));
    BOOST_CHECK(r2["interrupted"].get_bool());
}

BOOST_AUTO_TEST_CASE(watch_rpc_roundtrip)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-rpc";
    BindModelEventLayer(dir, 16);
    UniValue wp(UniValue::VOBJ);
    wp.pushKV("publisher_id", "pub-rpc");
    wp.pushKV("action", "NOTIFY");
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(DispatchModelWatchRpc("watchmodelpublisher", RpcParamsObj(wp), result, code, err, nullptr));
    BOOST_CHECK(result.exists("watch_id"));
    BOOST_CHECK_EQUAL(result["filesystem_watch"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["spends"].get_bool(), false);
    UniValue listed;
    BOOST_REQUIRE(DispatchModelWatchRpc("listmodelwatches", UniValue(UniValue::VARR), listed, code, err, nullptr));
    BOOST_REQUIRE_EQUAL(listed["watches"].size(), 1U);

    ObserveResult o;
    BOOST_REQUIRE(JournalObserve(MakeSigned("pub-rpc", "m1"), o, err));
    UniValue ge;
    BOOST_REQUIRE(DispatchModelWatchRpc("getmodelevents", RpcParamsObj(UniValue(UniValue::VOBJ)), ge, code, err, nullptr));
    BOOST_REQUIRE_GE(ge["events"].size(), 1U);

    UniValue seq;
    BOOST_REQUIRE(DispatchModelWatchRpc("getmodeleventsequence", UniValue(UniValue::VARR), seq, code, err, nullptr));
    BOOST_CHECK(seq["sequence"].getInt<int64_t>() >= 1);
}

BOOST_AUTO_TEST_CASE(channel_sequence_rollback_and_update_event)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-channel";
    BindModelEventLayer(dir, 16);
    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    Digest48 mid{};
    mid.data[0] = 0x11;
    Digest48 mid2{};
    mid2.data[0] = 0x22;
    std::string uri1, uri2;
    BOOST_REQUIRE(EncodeResource(ResourceKind::MODEL, mid, uri1, err));
    BOOST_REQUIRE(EncodeResource(ResourceKind::MODEL, mid2, uri2, err));

    SignedChannel ch;
    ch.pubkey = pk;
    ch.name = "coder";
    ch.channel = "stable";
    ch.target_uri = uri1;
    ch.sequence = 1;
    ch.expiry = 0;
    BOOST_REQUIRE(SignSignedChannel(ch, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_REQUIRE(BoundModelWatchStore()->ApplySignedChannel(ch, err));

    SignedChannel got;
    BOOST_REQUIRE(BoundModelWatchStore()->GetChannel(ch.publisher_id, "coder", "stable", got));
    BOOST_CHECK_EQUAL(got.sequence, uint64_t{1});
    BOOST_CHECK(got.signature_ok);

    SignedChannel down = ch;
    down.target_uri = uri2;
    down.sequence = 1;
    BOOST_REQUIRE(SignSignedChannel(down, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_CHECK(!BoundModelWatchStore()->ApplySignedChannel(down, err));
    BOOST_CHECK(err.find("rollback") != std::string::npos);

    SignedChannel up = ch;
    up.target_uri = uri2;
    up.sequence = 2;
    BOOST_REQUIRE(SignSignedChannel(up, Span<const unsigned char>{sk.data(), sk.size()}, err));
    BOOST_REQUIRE(BoundModelWatchStore()->ApplySignedChannel(up, err));

    const auto events = BoundModelEventJournal()->ReplayAfter(0, 100);
    int channel_events = 0;
    for (const auto& ev : events) {
        if (ev.event_type == ModelEventType::CHANNEL_UPDATED) ++channel_events;
    }
    BOOST_CHECK_EQUAL(channel_events, 2);

    SignedChannel unsigned_ch = up;
    unsigned_ch.sequence = 3;
    unsigned_ch.sig.clear();
    unsigned_ch.signature_ok = false;
    BOOST_CHECK(!BoundModelWatchStore()->ApplySignedChannel(unsigned_ch, err));
}

BOOST_AUTO_TEST_CASE(channel_rejects_file_uri)
{
    using namespace modelnet;
    SignedChannel ch;
    ch.publisher_id = "x";
    ch.name = "coder";
    ch.channel = "latest";
    ch.target_uri = "file:///etc/passwd";
    ch.sequence = 1;
    std::string err;
    BOOST_CHECK(!VerifySignedChannel(ch, 0, err));
}

BOOST_AUTO_TEST_CASE(observemodelchannel_unsigned_rejected)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-channel-rpc-unsigned";
    BindModelEventLayer(dir, 16);
    ModelCatalog cat{dir, 8 << 20};

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    (void)sk;
    Digest48 mid{};
    mid.data[0] = 0x31;
    std::string uri;
    BOOST_REQUIRE(EncodeResource(ResourceKind::MODEL, mid, uri, err));

    SignedChannel ch;
    ch.pubkey = pk;
    ch.name = "coder";
    ch.channel = "stable";
    ch.target_uri = uri;
    ch.sequence = 1;
    ch.expiry = 0;
    ch.sig.clear();
    ch.signature_ok = false;
    ch.publisher_id = ResearchIdentityId(Span<const unsigned char>{pk.data(), pk.size()}).Hex();

    UniValue result;
    std::string code;
    BOOST_REQUIRE(!DispatchModelWatchRpc("observemodelchannel", RpcParamsObj(ChannelRpcObj(ch)), result, code, err, nullptr));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK(err.find("unsigned") != std::string::npos);

    code.clear();
    err.clear();
    BOOST_REQUIRE(!DispatchHelperRpc(cat, HelperReq("observemodelchannel", ChannelRpcObj(ch)), result, code, err));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK(err.find("unsigned") != std::string::npos);

    SignedChannel stored;
    BOOST_CHECK(!BoundModelWatchStore()->GetChannel(ch.publisher_id, ch.name, ch.channel, stored));
    UniValue listed;
    BOOST_REQUIRE(DispatchModelWatchRpc("listmodelchannels", UniValue(UniValue::VARR), listed, code, err, nullptr));
    BOOST_CHECK(!ListHasChannel(listed, ch));
    BOOST_REQUIRE(DispatchHelperRpc(cat, HelperReq("listmodelchannels", UniValue(UniValue::VARR)), listed, code, err));
    BOOST_CHECK(!ListHasChannel(listed, ch));
}

BOOST_AUTO_TEST_CASE(observemodelchannel_signed_rpc_roundtrip)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-channel-rpc-signed";
    BindModelEventLayer(dir, 16);
    ModelCatalog cat{dir, 8 << 20};

    std::vector<unsigned char> pk, sk;
    std::string err;
    BOOST_REQUIRE(GenerateMlDsa44(pk, sk, err));
    Digest48 mid{};
    mid.data[0] = 0x41;
    std::string uri;
    BOOST_REQUIRE(EncodeResource(ResourceKind::MODEL, mid, uri, err));

    SignedChannel ch;
    ch.pubkey = pk;
    ch.name = "coder";
    ch.channel = "stable";
    ch.target_uri = uri;
    ch.sequence = 1;
    ch.expiry = 0;
    BOOST_REQUIRE(SignSignedChannel(ch, Span<const unsigned char>{sk.data(), sk.size()}, err));

    UniValue observed;
    std::string code;
    BOOST_REQUIRE(DispatchModelWatchRpc("observemodelchannel", RpcParamsObj(ChannelRpcObj(ch)), observed, code, err, nullptr));
    BOOST_CHECK_EQUAL(observed["sequence"].getInt<int64_t>(), static_cast<int64_t>(ch.sequence));
    BOOST_CHECK_EQUAL(observed["target_uri"].get_str(), uri);
    BOOST_CHECK(observed["signature_ok"].get_bool());
    AssertZeroSpendNoWallet(observed);

    SignedChannel via_helper_ch = ch;
    via_helper_ch.name = "tools";
    BOOST_REQUIRE(SignSignedChannel(via_helper_ch, Span<const unsigned char>{sk.data(), sk.size()}, err));
    UniValue helper_obs;
    BOOST_REQUIRE_MESSAGE(
        DispatchHelperRpc(cat, HelperReq("observemodelchannel", ChannelRpcObj(via_helper_ch)), helper_obs, code, err), err);
    BOOST_CHECK_EQUAL(helper_obs["sequence"].getInt<int64_t>(), static_cast<int64_t>(via_helper_ch.sequence));
    BOOST_CHECK_EQUAL(helper_obs["target_uri"].get_str(), uri);
    AssertZeroSpendNoWallet(helper_obs);

    UniValue getp(UniValue::VOBJ);
    getp.pushKV("publisher_id", ch.publisher_id);
    getp.pushKV("name", ch.name);
    getp.pushKV("channel", ch.channel);
    UniValue got;
    BOOST_REQUIRE(DispatchModelWatchRpc("getmodelchannel", RpcParamsObj(getp), got, code, err, nullptr));
    BOOST_CHECK_EQUAL(got["sequence"].getInt<int64_t>(), static_cast<int64_t>(ch.sequence));
    BOOST_CHECK_EQUAL(got["target_uri"].get_str(), uri);
    AssertZeroSpendNoWallet(got);

    UniValue helper_got;
    BOOST_REQUIRE(DispatchHelperRpc(cat, HelperReq("getmodelchannel", getp), helper_got, code, err));
    BOOST_CHECK_EQUAL(helper_got["sequence"].getInt<int64_t>(), static_cast<int64_t>(ch.sequence));
    BOOST_CHECK_EQUAL(helper_got["target_uri"].get_str(), uri);
    AssertZeroSpendNoWallet(helper_got);

    UniValue get_helper_ch(UniValue::VOBJ);
    get_helper_ch.pushKV("publisher_id", via_helper_ch.publisher_id);
    get_helper_ch.pushKV("name", via_helper_ch.name);
    get_helper_ch.pushKV("channel", via_helper_ch.channel);
    UniValue got_helper_ch;
    BOOST_REQUIRE(DispatchModelWatchRpc("getmodelchannel", RpcParamsObj(get_helper_ch), got_helper_ch, code, err, nullptr));
    BOOST_CHECK_EQUAL(got_helper_ch["sequence"].getInt<int64_t>(), static_cast<int64_t>(via_helper_ch.sequence));
    BOOST_CHECK_EQUAL(got_helper_ch["target_uri"].get_str(), uri);
    AssertZeroSpendNoWallet(got_helper_ch);

    UniValue listed;
    BOOST_REQUIRE(DispatchModelWatchRpc("listmodelchannels", UniValue(UniValue::VARR), listed, code, err, nullptr));
    BOOST_CHECK(ListHasChannel(listed, ch));
    BOOST_CHECK(ListHasChannel(listed, via_helper_ch));
    AssertZeroSpendNoWallet(listed);

    UniValue helper_listed;
    BOOST_REQUIRE(DispatchHelperRpc(cat, HelperReq("listmodelchannels", UniValue(UniValue::VARR)), helper_listed, code, err));
    BOOST_CHECK(ListHasChannel(helper_listed, ch));
    BOOST_CHECK(ListHasChannel(helper_listed, via_helper_ch));
    AssertZeroSpendNoWallet(helper_listed);
}

BOOST_AUTO_TEST_CASE(observemodelchannel_file_uri_rejected)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-channel-rpc-file";
    BindModelEventLayer(dir, 16);
    ModelCatalog cat{dir, 8 << 20};

    UniValue p(UniValue::VOBJ);
    p.pushKV("publisher_id", "x");
    p.pushKV("name", "coder");
    p.pushKV("channel", "latest");
    p.pushKV("target_uri", "file:///etc/passwd");
    p.pushKV("sequence", 1);
    p.pushKV("signature", "");

    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(!DispatchModelWatchRpc("observemodelchannel", RpcParamsObj(p), result, code, err, nullptr));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK(err.find("target_uri") != std::string::npos);

    code.clear();
    err.clear();
    BOOST_REQUIRE(!DispatchHelperRpc(cat, HelperReq("observemodelchannel", p), result, code, err));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK(err.find("target_uri") != std::string::npos);

    SignedChannel stored;
    BOOST_CHECK(!BoundModelWatchStore()->GetChannel("x", "coder", "latest", stored));
}

BOOST_AUTO_TEST_CASE(prepare_funding_action_is_unsigned)
{
    using namespace modelnet;
    QueuedWatchAction a;
    a.watch_id = "w1";
    a.action = ActionPolicy::PREPARE_FUNDING;
    a.object_id = "m1";
    a.event_id = "e1";
    a.job_id = "j1";
    const UniValue o = WatchActionToJson(a);
    BOOST_CHECK_EQUAL(o["action"].get_str(), "PREPARE_FUNDING");
    BOOST_CHECK(o["unsigned"].get_bool());
    BOOST_CHECK(!o["wallet_signed"].get_bool());
    BOOST_CHECK(!o["wallet"].get_bool());
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!o["spends"].get_bool());
}

BOOST_AUTO_TEST_CASE(fund_with_mandate_action_is_unsigned)
{
    using namespace modelnet;
    QueuedWatchAction a;
    a.watch_id = "w1";
    a.action = ActionPolicy::FUND_WITH_MANDATE;
    a.object_id = "m1";
    a.event_id = "e1";
    a.job_id = "j1";
    a.mandate_id = "mid-1";
    a.requires_mandate = true;
    const UniValue o = WatchActionToJson(a);
    BOOST_CHECK_EQUAL(o["action"].get_str(), "FUND_WITH_MANDATE");
    BOOST_CHECK(o["unsigned"].get_bool());
    BOOST_CHECK(!o["wallet_signed"].get_bool());
    BOOST_CHECK(!o["wallet"].get_bool());
    BOOST_CHECK(o["requires_mandate"].get_bool());
    BOOST_CHECK_EQUAL(o["mandate_id"].get_str(), "mid-1");
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!o["spends"].get_bool());
}

BOOST_AUTO_TEST_CASE(drain_actions_drops_fund_when_mandate_revoked_or_missing)
{
    using namespace modelnet;
    GlobalSubscriptionStore().Reset();
    ModelWatchStore store(m_path_root / "watch-fund-revoke");

    UniValue created;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(GlobalSubscriptionStore().Dispatch("createsubscriptionmandate", MandateRpcArr(WatchMandateJson("watch-mid")),
                                                             created, code, err, 1'000'000),
                          err);
    const std::string mid = created["mandate_id"].get_str();
    BOOST_CHECK_EQUAL(mid, "watch-mid");

    ModelWatch fund;
    fund.kind = WatchKind::PUBLISHER;
    fund.publisher_id = "pub-fund";
    fund.action = ActionPolicy::FUND_WITH_MANDATE;
    fund.mandate_id = mid;
    BOOST_REQUIRE(store.PutWatch(fund, err));

    ModelWatch keep;
    keep.kind = WatchKind::PUBLISHER;
    keep.publisher_id = "pub-fund";
    keep.action = ActionPolicy::KEEP;
    BOOST_REQUIRE(store.PutWatch(keep, err));

    store.NoteEvent(MakeSigned("pub-fund", "mid-live"));
    {
        const auto live = store.DrainActions();
        BOOST_REQUIRE_EQUAL(CountFundActions(live), 1U);
        bool saw_keep = false;
        for (const auto& a : live) {
            BOOST_CHECK(!a.spends);
            const UniValue j = WatchActionToJson(a);
            BOOST_CHECK_EQUAL(j["automatic_spend_atoms"].getInt<int>(), 0);
            if (a.action == ActionPolicy::KEEP) saw_keep = true;
        }
        BOOST_CHECK(saw_keep);
    }

    store.NoteEvent(MakeSigned("pub-fund", "mid-queued"));
    BOOST_CHECK_GE(CountFundActions(store.PeekActions()), 1U);

    UniValue revoked;
    BOOST_REQUIRE_MESSAGE(GlobalSubscriptionStore().Dispatch("revokesubscriptionmandate", MandateRpcArr(WatchMandateJson("watch-mid")),
                                                             revoked, code, err, 1'000'000),
                          err);
    BOOST_CHECK(revoked["revoked"].get_bool());

    UniValue status;
    BOOST_REQUIRE_MESSAGE(GlobalSubscriptionStore().Dispatch("getsubscriptionmandate", MandateRpcArr(WatchMandateJson("watch-mid")),
                                                             status, code, err, 1'000'000),
                          err);
    BOOST_CHECK(status["revoked"].get_bool());

    // Enqueue may still hold FUND; Drain is the admission gate.
    const auto after_revoke = store.DrainActions();
    BOOST_CHECK_EQUAL(CountFundActions(after_revoke), 0U);
    bool saw_keep_after = false;
    for (const auto& a : after_revoke) {
        BOOST_CHECK(a.action != ActionPolicy::FUND_WITH_MANDATE);
        BOOST_CHECK(!a.spends);
        BOOST_CHECK_EQUAL(WatchActionToJson(a)["automatic_spend_atoms"].getInt<int>(), 0);
        if (a.action == ActionPolicy::KEEP) saw_keep_after = true;
    }
    BOOST_CHECK(saw_keep_after);

    store.NoteEvent(MakeSigned("pub-fund", "mid-after-revoke"));
    const auto queued_after = store.DrainActions();
    BOOST_CHECK_EQUAL(CountFundActions(queued_after), 0U);

    ModelWatch missing;
    missing.kind = WatchKind::PUBLISHER;
    missing.publisher_id = "pub-missing";
    missing.action = ActionPolicy::FUND_WITH_MANDATE;
    missing.mandate_id = "no-such-mandate";
    BOOST_REQUIRE(store.PutWatch(missing, err));
    store.NoteEvent(MakeSigned("pub-missing", "mid-absent"));
    BOOST_CHECK_GE(CountFundActions(store.PeekActions()), 1U);
    const auto absent = store.DrainActions();
    BOOST_CHECK_EQUAL(CountFundActions(absent), 0U);
    for (const auto& a : absent) {
        BOOST_CHECK(a.action != ActionPolicy::FUND_WITH_MANDATE);
        BOOST_CHECK(!a.spends);
    }

    GlobalSubscriptionStore().Reset();
}

BOOST_AUTO_TEST_CASE(remaining_watch_collection_query_get_unwatch_helper)
{
    using namespace modelnet;
    const fs::path dir = m_path_root / "watch-remain-rpc";
    BindModelEventLayer(dir, 16);
    ModelCatalog cat{dir, 8 << 20};
    UniValue result;
    std::string code, err;

    UniValue coll(UniValue::VOBJ);
    coll.pushKV("collection_id", "col-remain-1");
    coll.pushKV("action", "NOTIFY");
    BOOST_REQUIRE_MESSAGE(DispatchModelWatchRpc("watchmodelcollection", RpcParamsObj(coll), result, code, err, nullptr), err);
    BOOST_REQUIRE(result.exists("watch_id"));
    BOOST_CHECK_EQUAL(result["kind"].get_str(), "COLLECTION");
    BOOST_CHECK_EQUAL(result["collection_id"].get_str(), "col-remain-1");
    AssertZeroSpendNoWallet(result);
    const std::string coll_id = result["watch_id"].get_str();

    UniValue q(UniValue::VOBJ);
    q.pushKV("text", "ops");
    q.pushKV("action", "NOTIFY");
    q.pushKV("filters", UniValue(UniValue::VOBJ));
    BOOST_REQUIRE_MESSAGE(DispatchModelWatchRpc("watchmodelquery", RpcParamsObj(q), result, code, err, nullptr), err);
    BOOST_CHECK_EQUAL(result["kind"].get_str(), "QUERY");
    BOOST_CHECK_EQUAL(result["query_text"].get_str(), "ops");
    AssertZeroSpendNoWallet(result);
    const std::string query_id = result["watch_id"].get_str();

    UniValue mw(UniValue::VOBJ);
    mw.pushKV("model_id", std::string(96, 'e'));
    mw.pushKV("action", "NOTIFY");
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, HelperReq("watchmodel", mw), result, code, err), err);
    BOOST_CHECK_EQUAL(result["kind"].get_str(), "MODEL");
    AssertZeroSpendNoWallet(result);
    const std::string model_wid = result["watch_id"].get_str();

    UniValue gotp(UniValue::VOBJ);
    gotp.pushKV("watch_id", coll_id);
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, HelperReq("getmodelwatch", gotp), result, code, err), err);
    BOOST_CHECK_EQUAL(result["watch_id"].get_str(), coll_id);
    BOOST_CHECK_EQUAL(result["collection_id"].get_str(), "col-remain-1");
    AssertZeroSpendNoWallet(result);

    UniValue listed;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, HelperReq("listmodelwatches", UniValue(UniValue::VARR)), listed, code, err), err);
    BOOST_REQUIRE(listed["watches"].isArray());
    BOOST_CHECK_GE(listed["watches"].size(), 3U);
    AssertZeroSpendNoWallet(listed);

    UniValue acts;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, HelperReq("getmodelwatchactions", UniValue(UniValue::VOBJ)), acts, code, err), err);
    BOOST_REQUIRE(acts["actions"].isArray());
    AssertZeroSpendNoWallet(acts);

    UniValue un(UniValue::VOBJ);
    un.pushKV("watch_id", query_id);
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, HelperReq("unwatchmodel", un), result, code, err), err);
    BOOST_CHECK(result["removed"].get_bool());
    BOOST_CHECK_EQUAL(result["watch_id"].get_str(), query_id);

    UniValue missing;
    BOOST_CHECK(!DispatchModelWatchRpc("getmodelwatch", RpcParamsObj(un), missing, code, err, nullptr));
    BOOST_CHECK_EQUAL(code, "NOT_FOUND");

    UniValue un2(UniValue::VOBJ);
    un2.pushKV("watch_id", model_wid);
    BOOST_REQUIRE_MESSAGE(DispatchModelWatchRpc("unwatchmodel", RpcParamsObj(un2), result, code, err, nullptr), err);
    BOOST_CHECK(result["removed"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
