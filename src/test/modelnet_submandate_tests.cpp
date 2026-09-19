// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit/.

#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/subscription_mandate.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_submandate_tests, BasicTestingSetup)

namespace {

using namespace modelnet;

const int64_t kNow = 1'000'000;
const int64_t kExp = 2'000'000;

std::string HexN(size_t n, char c)
{
    return std::string(n, c);
}

UniValue BaseMandateJson()
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", 1);
    o.pushKV("owner_identity", HexN(96, 'a'));
    o.pushKV("network_id", HexN(64, '0'));
    o.pushKV("publisher_id", HexN(96, 'b'));
    UniValue kinds(UniValue::VARR);
    kinds.push_back("RELEASE");
    kinds.push_back("MODEL");
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    acts.push_back("PREPARE_FUNDING");
    acts.push_back("NOTIFY");
    o.pushKV("allowed_actions", acts);
    o.pushKV("per_action_principal_limit_atoms", "50");
    o.pushKV("total_principal_limit_atoms", "100");
    o.pushKV("total_fee_limit_atoms", "20");
    o.pushKV("outstanding_exposure_limit_atoms", "200");
    o.pushKV("max_actions", 16);
    o.pushKV("max_concurrent_reservations", 8);
    o.pushKV("expires_at_ms", std::to_string(kExp));
    o.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    o.pushKV("minimum_confirmations", 1);
    o.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    o.pushKV("revocation_counter", "0");
    return o;
}

SubscriptionMandate MustParse(const UniValue& o)
{
    SubscriptionMandate m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(MandateFromJson(o, m, err), err);
    return m;
}

void BoundBudget(SubscriptionBudget& b, const UniValue& o, const std::string& id = "mid-1")
{
    SubscriptionMandate m = MustParse(o);
    m.mandate_id = id;
    std::string err;
    BOOST_REQUIRE_MESSAGE(ValidateMandate(m, err), err);
    BOOST_REQUIRE_MESSAGE(b.Bind(m, err), err);
}

SubscriptionEvent FundEvent(const std::string& event_id, const std::string& publisher, const std::string& mid)
{
    SubscriptionEvent ev;
    ev.event_id = event_id;
    ev.publisher_id = publisher;
    ev.object_kind = "RELEASE";
    ev.object_id = "obj-1";
    ev.action = "FUND_WITH_MANDATE";
    ev.mandate_id = mid;
    ev.observed_at_ms = kNow;
    return ev;
}

SignedTerms KnownTerms(const std::string& publisher, int64_t principal, int64_t fee)
{
    SignedTerms t;
    t.known = true;
    t.terms_id = HexN(96, 'd');
    t.publisher_id = publisher;
    t.network_id_hex = HexN(64, '0');
    t.principal_atoms = principal;
    t.fee_atoms = fee;
    t.object_kind = "RELEASE";
    t.confirmations = 1;
    t.refund_key = "owner-refund";
    return t;
}

UniValue Arr(const UniValue& o)
{
    UniValue a(UniValue::VARR);
    a.push_back(o);
    return a;
}

UniValue Rpc(const std::string& method, const UniValue& params = UniValue(UniValue::VARR))
{
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

void AssertHelperNoWallet(const UniValue& o)
{
    BOOST_REQUIRE(o.isObject());
    BOOST_CHECK(!o["wallet_signed"].get_bool());
    BOOST_CHECK(!o.exists("private_key"));
    BOOST_CHECK(!o.exists("wallet_seed"));
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

UniValue Without(const UniValue& o, const std::string& key)
{
    UniValue n(UniValue::VOBJ);
    for (const auto& k : o.getKeys()) {
        if (k != key) n.pushKV(k, o[k]);
    }
    return n;
}

} // namespace

BOOST_AUTO_TEST_CASE(mandate_sub_01_unknown_terms_cannot_bypass_publisher)
{
    using namespace modelnet;
    const auto j = BaseMandateJson();
    SubscriptionMandate m = MustParse(j);
    m.mandate_id = "mid-1";
    std::string err;

    SubscriptionEvent ev = FundEvent("e-unknown-q", HexN(96, 'c'), "mid-1");
    SignedTerms unknown;
    unknown.known = false;
    BOOST_CHECK(!Evaluate(ev, unknown, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "publisher binding");

    ev.publisher_id = HexN(96, 'b');
    err.clear();
    BOOST_CHECK(!Evaluate(ev, unknown, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "unknown terms");

    SignedTerms other = KnownTerms(HexN(96, 'c'), 10, 1);
    err.clear();
    BOOST_CHECK(!Evaluate(ev, other, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "publisher binding");
}

BOOST_AUTO_TEST_CASE(mandate_sub_02_nested_recipient_tricks_rejected)
{
    using namespace modelnet;
    SubscriptionMandate m = MustParse(BaseMandateJson());
    m.mandate_id = "mid-1";
    std::string err;
    SubscriptionEvent ev = FundEvent("e-nest", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 10, 1);
    t.nested_recipient = "attacker";
    BOOST_CHECK(!Evaluate(ev, t, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "nested recipient");

    t = KnownTerms(HexN(96, 'b'), 10, 1);
    t.recipients = {HexN(96, 'b'), HexN(96, 'c')};
    err.clear();
    BOOST_CHECK(!Evaluate(ev, t, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "nested recipient");

    t = KnownTerms(HexN(96, 'b'), 10, 1);
    t.all_recipients = true;
    err.clear();
    BOOST_CHECK(!Evaluate(ev, t, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "all recipients");

    t = KnownTerms(HexN(96, 'b'), 10, 1);
    t.raw.setObject();
    t.raw.pushKV("pay_to", "attacker");
    err.clear();
    BOOST_CHECK(!Evaluate(ev, t, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "nested recipient");

    ev.nested_publisher_id = HexN(96, 'c');
    t = KnownTerms(HexN(96, 'b'), 10, 1);
    err.clear();
    BOOST_CHECK(!Evaluate(ev, t, m, kNow, err));
    BOOST_CHECK_EQUAL(err, "nested publisher");
}

BOOST_AUTO_TEST_CASE(mandate_sub_03_concurrent_cannot_exceed_budget)
{
    using namespace modelnet;
    auto j = BaseMandateJson();
    j.pushKV("per_action_principal_limit_atoms", "50");
    j.pushKV("total_principal_limit_atoms", "100");
    j.pushKV("max_concurrent_reservations", 8);
    SubscriptionBudget budget;
    BoundBudget(budget, j);
    std::atomic<int> ok{0};
    std::vector<std::thread> th;
    th.reserve(8);
    for (int i = 0; i < 8; ++i) {
        th.emplace_back([&, i] {
            SubscriptionEvent ev = FundEvent("e-conc-" + std::to_string(i), HexN(96, 'b'), "mid-1");
            SignedTerms t = KnownTerms(HexN(96, 'b'), 40, 1);
            Reservation r;
            std::string e;
            if (EvaluateAndReserve(budget, ev, t, r, kNow, e)) ++ok;
        });
    }
    for (auto& t : th) t.join();
    BOOST_CHECK_LE(ok.load(), 2);
    BOOST_CHECK_LE(budget.UsedPrincipal(), 100);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal() % 40, 0);
    BOOST_CHECK_EQUAL(budget.UsedFees(), ok.load());
}

BOOST_AUTO_TEST_CASE(mandate_sub_04_duplicate_event_cannot_double_spend)
{
    using namespace modelnet;
    SubscriptionBudget budget;
    BoundBudget(budget, BaseMandateJson());
    SubscriptionEvent ev = FundEvent("e-dup", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 40, 2);
    Reservation r1, r2;
    std::string err;
    BOOST_REQUIRE(EvaluateAndReserve(budget, ev, t, r1, kNow, err));
    BOOST_REQUIRE(EvaluateAndReserve(budget, ev, t, r2, kNow, err));
    BOOST_CHECK_EQUAL(r1.reservation_id, r2.reservation_id);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 2);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 1);
    SignedTerms t2 = KnownTerms(HexN(96, 'b'), 50, 2);
    Reservation r3;
    BOOST_CHECK(!EvaluateAndReserve(budget, ev, t2, r3, kNow, err));
    BOOST_CHECK_EQUAL(err, "idempotency conflict");
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
}

BOOST_AUTO_TEST_CASE(mandate_sub_05_reorg_does_not_refund_spend_budget)
{
    using namespace modelnet;
    SubscriptionBudget budget;
    BoundBudget(budget, BaseMandateJson());
    SubscriptionEvent ev = FundEvent("e-reorg", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 40, 3);
    Reservation r;
    std::string err;
    BOOST_REQUIRE(EvaluateAndReserve(budget, ev, t, r, kNow, err));
    BOOST_REQUIRE(budget.MarkBroadcast("e-reorg", err));
    const int64_t principal = budget.UsedPrincipal();
    const int64_t fees = budget.UsedFees();
    budget.NoteChainReorg();
    BOOST_CHECK_EQUAL(budget.ReorgCount(), 1);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), principal);
    BOOST_CHECK_EQUAL(budget.UsedFees(), fees);
    budget.NoteChainReorg();
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 3);
}

BOOST_AUTO_TEST_CASE(mandate_sub_06_revoke_blocks_new_signatures)
{
    using namespace modelnet;
    SubscriptionBudget budget;
    BoundBudget(budget, BaseMandateJson());
    std::string err;
    budget.Revoke();
    BOOST_CHECK(budget.Revoked());
    SubscriptionEvent ev = FundEvent("e-rev", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 10, 1);
    Reservation r;
    BOOST_CHECK(!EvaluateAndReserve(budget, ev, t, r, kNow, err));
    BOOST_CHECK_EQUAL(err, "revoked");
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 0);
}

BOOST_AUTO_TEST_CASE(mandate_sub_07_broadcast_transactions_remain_real)
{
    using namespace modelnet;
    SubscriptionBudget budget;
    BoundBudget(budget, BaseMandateJson());
    SubscriptionEvent ev = FundEvent("e-bc", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 40, 1);
    Reservation r;
    std::string err;
    BOOST_REQUIRE(EvaluateAndReserve(budget, ev, t, r, kNow, err));
    BOOST_REQUIRE(budget.MarkBroadcast("e-bc", err));
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    budget.Revoke();
    SubscriptionEvent ev2 = FundEvent("e-bc-2", HexN(96, 'b'), "mid-1");
    Reservation r2;
    BOOST_CHECK(!EvaluateAndReserve(budget, ev2, t, r2, kNow, err));
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 1);
    UniValue st = budget.StatusJson();
    BOOST_CHECK(st["revoked"].get_bool());
    BOOST_CHECK_EQUAL(st["used_principal_atoms"].get_str(), "40");
}

BOOST_AUTO_TEST_CASE(mandate_sub_08_expiry_enforced)
{
    using namespace modelnet;
    std::string err;
    UniValue missing = Without(BaseMandateJson(), "expires_at_ms");
    SubscriptionMandate bad;
    BOOST_CHECK(!MandateFromJson(missing, bad, err));
    BOOST_CHECK_EQUAL(err, "expires_at_ms");

    UniValue zero = BaseMandateJson();
    zero.pushKV("expires_at_ms", "0");
    BOOST_CHECK(!MandateFromJson(zero, bad, err));

    UniValue wild = BaseMandateJson();
    wild.pushKV("publisher_id", "*");
    BOOST_CHECK(!MandateFromJson(wild, bad, err));
    wild = BaseMandateJson();
    wild.pushKV("all_publishers", true);
    BOOST_CHECK(!MandateFromJson(wild, bad, err));
    BOOST_CHECK_EQUAL(err, "wildcard");

    SubscriptionMandate m = MustParse(BaseMandateJson());
    m.mandate_id = "mid-1";
    SubscriptionEvent ev = FundEvent("e-exp", HexN(96, 'b'), "mid-1");
    SignedTerms t = KnownTerms(HexN(96, 'b'), 10, 1);
    BOOST_CHECK(!Evaluate(ev, t, m, kExp + 1, err));
    BOOST_CHECK_EQUAL(err, "expired");

    SubscriptionBudget budget;
    BoundBudget(budget, BaseMandateJson());
    Reservation r;
    BOOST_CHECK(!EvaluateAndReserve(budget, ev, t, r, kExp + 1, err));
    BOOST_CHECK(budget.Expired(kExp + 1));
}

BOOST_AUTO_TEST_CASE(mandate_sub_09_fees_count_separately)
{
    using namespace modelnet;
    auto j = BaseMandateJson();
    j.pushKV("total_fee_limit_atoms", "5");
    j.pushKV("per_action_principal_limit_atoms", "50");
    SubscriptionBudget budget;
    BoundBudget(budget, j);
    std::string err;
    UniValue missing = Without(BaseMandateJson(), "total_fee_limit_atoms");
    SubscriptionMandate bad;
    BOOST_CHECK(!MandateFromJson(missing, bad, err));
    BOOST_CHECK_EQUAL(err, "missing caps");

    SubscriptionEvent ev1 = FundEvent("e-fee-1", HexN(96, 'b'), "mid-1");
    SignedTerms t1 = KnownTerms(HexN(96, 'b'), 40, 4);
    Reservation r;
    BOOST_REQUIRE(EvaluateAndReserve(budget, ev1, t1, r, kNow, err));
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 4);
    SubscriptionEvent ev2 = FundEvent("e-fee-2", HexN(96, 'b'), "mid-1");
    SignedTerms t2 = KnownTerms(HexN(96, 'b'), 10, 2);
    BOOST_CHECK(!EvaluateAndReserve(budget, ev2, t2, r, kNow, err));
    BOOST_CHECK_EQUAL(err, "fee budget");
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 40);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 4);
}

BOOST_AUTO_TEST_CASE(mandate_sub_10_helper_never_receives_wallet_key)
{
    using namespace modelnet;
    BOOST_CHECK_EQUAL(SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS, 0);
    WatchActionPolicy def;
    std::string err;
    BOOST_REQUIRE(ValidateWatchActionPolicy(def, err));
    BOOST_CHECK_EQUAL(std::string(WatchActionName(def.action)), "NOTIFY");
    WatchActionPolicy fund;
    fund.action = WatchAction::FUND_WITH_MANDATE;
    BOOST_CHECK(!ValidateWatchActionPolicy(fund, err));
    BOOST_CHECK_EQUAL(err, "FUND_WITH_MANDATE requires mandate_id");
    fund.mandate_id = "mid-1";
    BOOST_REQUIRE(ValidateWatchActionPolicy(fund, err));

    SubscriptionMandate m = MustParse(BaseMandateJson());
    m.mandate_id = "mid-1";
    SubscriptionEvent naked = FundEvent("e-noid", HexN(96, 'b'), "");
    BOOST_CHECK(!Evaluate(naked, KnownTerms(HexN(96, 'b'), 10, 1), m, kNow, err));
    BOOST_CHECK_EQUAL(err, "FUND_WITH_MANDATE requires mandate_id");

    SubscriptionStore store;
    UniValue created;
    std::string code;
    BOOST_REQUIRE(store.Dispatch("createsubscriptionmandate", Arr(BaseMandateJson()), created, code, err, kNow));
    BOOST_CHECK_EQUAL(created["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!created["private_keys"].get_bool());
    BOOST_CHECK(!created["wallet_signed"].get_bool());
    const std::string mid = created["mandate_id"].get_str();

    UniValue rsv(UniValue::VOBJ);
    rsv.pushKV("mandate_id", mid);
    rsv.pushKV("event_id", "e-key");
    rsv.pushKV("publisher_id", HexN(96, 'b'));
    rsv.pushKV("object_kind", "RELEASE");
    rsv.pushKV("action", "FUND_WITH_MANDATE");
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("terms_id", HexN(96, 'd'));
    terms.pushKV("publisher_id", HexN(96, 'b'));
    terms.pushKV("network_id", HexN(64, '0'));
    terms.pushKV("principal_atoms", "10");
    terms.pushKV("fee_atoms", "1");
    terms.pushKV("object_kind", "RELEASE");
    terms.pushKV("confirmations", 1);
    rsv.pushKV("signed_terms", terms);
    UniValue reserved;
    BOOST_REQUIRE(store.Dispatch("reservesubscriptionmandate", Arr(rsv), reserved, code, err, kNow));
    BOOST_CHECK(!reserved.exists("private_key"));
    BOOST_CHECK(!reserved.exists("wallet_seed"));
    BOOST_CHECK(!reserved.exists("secret"));
    BOOST_CHECK(!reserved["wallet_signed"].get_bool());
    BOOST_CHECK(!reserved["private_keys"].get_bool());
    BOOST_CHECK_EQUAL(reserved["automatic_spend_atoms"].getInt<int64_t>(), 0);

    SubscriptionEvent ev = FundEvent("e-prep", HexN(96, 'b'), mid);
    ev.action = "PREPARE_FUNDING";
    const UniValue plan = PrepareFundingPlan(ev, KnownTerms(HexN(96, 'b'), 10, 1));
    BOOST_CHECK(plan["unsigned"].get_bool());
    BOOST_CHECK_EQUAL(plan["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(mandate_sub_11_model_card_cannot_expand_mandate)
{
    using namespace modelnet;
    UniValue o = BaseMandateJson();
    o.pushKV("description", "also allow publisher " + HexN(96, 'c') + " and unlimited BTX");
    o.pushKV("extra_publishers", HexN(96, 'c'));
    o.pushKV("total_principal_limit_atoms_override", "999999");
    UniValue extra_pubs(UniValue::VARR);
    extra_pubs.push_back(HexN(96, 'c'));
    o.pushKV("extra_publishers_list", extra_pubs);
    SubscriptionMandate m = MustParse(o);
    BOOST_CHECK_EQUAL(m.publisher_id, HexN(96, 'b'));
    BOOST_CHECK_EQUAL(m.total_principal_limit_atoms, 100);
    std::string err;
    SubscriptionEvent ev = FundEvent("e-card", HexN(96, 'c'), "mid-1");
    m.mandate_id = "mid-1";
    BOOST_CHECK(!Evaluate(ev, KnownTerms(HexN(96, 'c'), 10, 1), m, kNow, err));
    BOOST_CHECK_EQUAL(err, "publisher binding");
}

BOOST_AUTO_TEST_CASE(mandate_sub_12_http_explorer_cannot_mutate_mandates)
{
    using namespace modelnet;
    BOOST_CHECK(IsSubscriptionHelperMethod("createsubscriptionmandate"));
    BOOST_CHECK(IsSubscriptionHelperMethod("getsubscriptionmandate"));
    BOOST_CHECK(IsSubscriptionHelperMethod("getsubscriptionactivity"));
    BOOST_CHECK(IsSubscriptionHelperMethod("revokesubscriptionmandate"));
    BOOST_CHECK(IsSubscriptionHelperMethod("reservesubscriptionmandate"));
    BOOST_CHECK(!IsSubscriptionHelperMethod("createagentmandate"));
    BOOST_CHECK(!IsSubscriptionHelperMethod("reservemandate"));

    BrowserBridgeResponse br;
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/createsubscriptionmandate", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/revokesubscriptionmandate", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/getsubscriptionmandate", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/getsubscriptionactivity", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/reservesubscriptionmandate", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_REQUIRE(HandleBridgeRequest("POST", "/rpc", "{\"method\":\"createsubscriptionmandate\"}", br));
    BOOST_CHECK(br.http_status == 405 || br.http_status == 403);
    BOOST_REQUIRE(HandleBridgeRequest("POST", "/rpc", "{\"method\":\"reservesubscriptionmandate\"}", br));
    BOOST_CHECK(br.http_status == 405 || br.http_status == 403);
    BOOST_REQUIRE(HandleBridgeRequest("GET", "/createagentmandate", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
}

BOOST_AUTO_TEST_CASE(remaining_subscription_helper_rpc)
{
    using namespace modelnet;
    ModelCatalog cat{m_path_root / "sub-helper", 1 << 20};
    std::string code, err;
    BOOST_CHECK_EQUAL(SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS, 0);

    UniValue j = Without(BaseMandateJson(), "expires_at_ms");
    j.pushKV("expires_at_ms", "4000000000000");

    UniValue created;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, Rpc("createsubscriptionmandate", Arr(j)), created, code, err), err);
    AssertHelperNoWallet(created);
    const std::string mid = created["mandate_id"].get_str();
    BOOST_REQUIRE(!mid.empty());

    UniValue getp(UniValue::VOBJ);
    getp.pushKV("mandate_id", mid);
    UniValue got;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, Rpc("getsubscriptionmandate", Arr(getp)), got, code, err), err);
    AssertHelperNoWallet(got);

    UniValue rsv(UniValue::VOBJ);
    rsv.pushKV("mandate_id", mid);
    rsv.pushKV("event_id", "e-helper");
    rsv.pushKV("publisher_id", HexN(96, 'b'));
    rsv.pushKV("object_kind", "RELEASE");
    rsv.pushKV("action", "FUND_WITH_MANDATE");
    UniValue terms(UniValue::VOBJ);
    terms.pushKV("terms_id", HexN(96, 'd'));
    terms.pushKV("publisher_id", HexN(96, 'b'));
    terms.pushKV("network_id", HexN(64, '0'));
    terms.pushKV("principal_atoms", "10");
    terms.pushKV("fee_atoms", "1");
    terms.pushKV("object_kind", "RELEASE");
    terms.pushKV("confirmations", 1);
    rsv.pushKV("signed_terms", terms);
    UniValue reserved;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, Rpc("reservesubscriptionmandate", Arr(rsv)), reserved, code, err), err);
    AssertHelperNoWallet(reserved);

    UniValue actp(UniValue::VOBJ);
    actp.pushKV("mandate_id", mid);
    actp.pushKV("limit", 10);
    UniValue activity;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, Rpc("getsubscriptionactivity", Arr(actp)), activity, code, err), err);
    AssertHelperNoWallet(activity);
    BOOST_REQUIRE(activity.exists("actions") && activity["actions"].isArray());
    BOOST_REQUIRE_EQUAL(activity["actions"].size(), 1U);
    BOOST_CHECK_EQUAL(activity["actions"][0]["event_id"].get_str(), "e-helper");
    BOOST_CHECK_EQUAL(activity["actions"][0]["terms_id"].get_str(), HexN(96, 'd'));
    BOOST_CHECK(activity["actions"][0]["txid"].get_str().empty());
    BOOST_CHECK(!activity["telemetry"].get_bool());
    BOOST_CHECK_EQUAL(activity["automatic_spend_atoms"].getInt<int64_t>(), 0);

    UniValue missing(UniValue::VOBJ);
    actp.pushKV("mandate_id", "no-such-mandate");
    BOOST_CHECK(!DispatchHelperRpc(cat, Rpc("getsubscriptionactivity", Arr(actp)), activity, code, err));
    BOOST_CHECK_EQUAL(code, "NOT_FOUND");

    UniValue badlim(UniValue::VOBJ);
    badlim.pushKV("mandate_id", mid);
    badlim.pushKV("limit", 0);
    BOOST_CHECK(!DispatchHelperRpc(cat, Rpc("getsubscriptionactivity", Arr(badlim)), activity, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue badcur(UniValue::VOBJ);
    badcur.pushKV("mandate_id", mid);
    badcur.pushKV("cursor", "no-such-event");
    BOOST_CHECK(!DispatchHelperRpc(cat, Rpc("getsubscriptionactivity", Arr(badcur)), activity, code, err));
    BOOST_CHECK_EQUAL(code, "INVALID_PARAMETER");

    UniValue revp(UniValue::VOBJ);
    revp.pushKV("mandate_id", mid);
    UniValue revoked;
    BOOST_REQUIRE_MESSAGE(DispatchHelperRpc(cat, Rpc("revokesubscriptionmandate", Arr(revp)), revoked, code, err), err);
    AssertHelperNoWallet(revoked);
    BOOST_CHECK(revoked["revoked"].get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
