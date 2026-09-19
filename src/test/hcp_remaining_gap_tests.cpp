// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Remaining unique HCP/1 + Cognitive Reserve v1.1 gaps that no other native TU
// covers: a stale observation stays an observation and never becomes a value
// input, and a mandate refuses to pay before the terms it pays for confirm.
// automatic_spend_atoms stays 0 in every case below.

#include <modelnet/subscription_mandate.h>
#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <string>

using namespace modelnet;

BOOST_FIXTURE_TEST_SUITE(hcp_remaining_gap_tests, BasicTestingSetup)

namespace {

const int64_t kMandateNow = 1'000'000;
const int64_t kMandateExpiry = 2'000'000;

std::string HexRun(size_t n, char c)
{
    return std::string(n, c);
}

const std::string kOwner = HexRun(96, 'a');
const std::string kPublisher = HexRun(96, 'b');
const std::string kTermsId = HexRun(96, 'd');
const std::string kNetwork = HexRun(64, '0');

//! Finite, single-publisher mandate. minimum_confirmations is the pre-pay bar.
UniValue MandateJson(const std::string& mandate_id, int minimum_confirmations)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", 1);
    o.pushKV("mandate_id", mandate_id);
    o.pushKV("owner_identity", kOwner);
    o.pushKV("network_id", kNetwork);
    o.pushKV("publisher_id", kPublisher);
    UniValue kinds(UniValue::VARR);
    kinds.push_back("RELEASE");
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    acts.push_back("FUND_WITH_MANDATE");
    acts.push_back("PREPARE_FUNDING");
    o.pushKV("allowed_actions", acts);
    o.pushKV("per_action_principal_limit_atoms", "50");
    o.pushKV("total_principal_limit_atoms", "100");
    o.pushKV("total_fee_limit_atoms", "20");
    o.pushKV("outstanding_exposure_limit_atoms", "200");
    o.pushKV("max_actions", 16);
    o.pushKV("max_concurrent_reservations", 8);
    o.pushKV("expires_at_ms", std::to_string(kMandateExpiry));
    o.pushKV("refund_key_policy", "OWNER_CONTROLLED_ONLY");
    o.pushKV("minimum_confirmations", minimum_confirmations);
    o.pushKV("assurance_mode_restrictions", UniValue(UniValue::VARR));
    o.pushKV("revocation_counter", "0");
    return o;
}

SubscriptionMandate ParsedMandate(const std::string& mandate_id, int minimum_confirmations)
{
    SubscriptionMandate m;
    std::string err;
    BOOST_REQUIRE_MESSAGE(MandateFromJson(MandateJson(mandate_id, minimum_confirmations), m, err), err);
    return m;
}

SubscriptionEvent FundEvent(const std::string& event_id, const std::string& mandate_id)
{
    SubscriptionEvent ev;
    ev.event_id = event_id;
    ev.publisher_id = kPublisher;
    ev.object_kind = "RELEASE";
    ev.object_id = "obj-prepay";
    ev.action = "FUND_WITH_MANDATE";
    ev.mandate_id = mandate_id;
    ev.observed_at_ms = kMandateNow;
    return ev;
}

//! Signed terms for one release. confirmations is the caller's knob.
SignedTerms Terms(int confirmations)
{
    SignedTerms t;
    t.known = true;
    t.terms_id = kTermsId;
    t.publisher_id = kPublisher;
    t.network_id_hex = kNetwork;
    t.principal_atoms = 10;
    t.fee_atoms = 1;
    t.object_kind = "RELEASE";
    t.confirmations = confirmations;
    t.refund_key = "owner-refund";
    return t;
}

UniValue TermsJson(int confirmations)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("terms_id", kTermsId);
    o.pushKV("publisher_id", kPublisher);
    o.pushKV("network_id", kNetwork);
    o.pushKV("object_kind", "RELEASE");
    o.pushKV("refund_key", "owner-refund");
    o.pushKV("principal_atoms", "10");
    o.pushKV("fee_atoms", "1");
    o.pushKV("confirmations", confirmations);
    return o;
}

UniValue Arr(const UniValue& o)
{
    UniValue a(UniValue::VARR);
    a.push_back(o);
    return a;
}

void CheckUnsignedAndZeroSpend(const UniValue& o)
{
    BOOST_REQUIRE(o.isObject());
    BOOST_CHECK(!o["wallet_signed"].get_bool());
    BOOST_CHECK(!o["private_keys"].get_bool());
    BOOST_CHECK(!o.exists("wallet_seed"));
    BOOST_CHECK_EQUAL(o["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

//! HCP/1 encodes integers as decimal strings on the wire.
int64_t Num(const UniValue& v)
{
    const auto n = ToIntegral<int64_t>(v.get_str());
    BOOST_REQUIRE_MESSAGE(n.has_value(), "not an integer: " + v.get_str());
    return *n;
}

} // namespace

// Gap: a reserve snapshot is an observation. Aging one must not promote it to a
// current fact, and the aged number must not be usable as a reporting-floor
// input. Refusing it must also not invent a number.
BOOST_AUTO_TEST_CASE(hcp_rem_01_stale_observation_stays_an_observation)
{
    auto e = cr11_test::Lab();
    const auto tok = cr11_test::Tok(*e);

    UniValue port(UniValue::VOBJ);
    port.pushKV("portfolio_id", "port-rem01");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &port));
    BOOST_REQUIRE_EQUAL(created.status, 201);

    const int64_t t0 = e->Now();
    auto first = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-rem01/snapshot", tok));
    BOOST_REQUIRE_EQUAL(first.status, 200);
    BOOST_REQUIRE_EQUAL(cr11_test::ObjType(first), modelnet::HCP_TYPE_RESERVE_SNAPSHOT);
    const UniValue observation = cr11_test::Json(first)["body"];
    BOOST_CHECK_EQUAL(Num(observation["observed_at"]), t0);
    // An observation is never a merged valuation.
    BOOST_CHECK(!observation["nav_merged"].get_bool());
    const int64_t seq0 = Num(observation["ledger_sequence"]);

    e->SetClock(t0 + 600'000);

    // Re-reading mints a new observation; the old one keeps its own timestamp
    // instead of being restamped as current.
    auto second = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-rem01/snapshot", tok));
    BOOST_REQUIRE_EQUAL(second.status, 200);
    const UniValue fresh = cr11_test::Json(second)["body"];
    BOOST_CHECK_EQUAL(Num(fresh["observed_at"]), e->Now());
    BOOST_CHECK_GT(Num(fresh["ledger_sequence"]), seq0);
    BOOST_CHECK_EQUAL(Num(observation["observed_at"]), t0);
    BOOST_CHECK_NE(observation["snapshot_id"].get_str(), fresh["snapshot_id"].get_str());

    // The aged observation cannot be spent as a price: the plan path refuses it
    // rather than silently substituting the current clock.
    UniValue body(UniValue::VOBJ);
    body.pushKV("required_quote", "1");
    body.pushKV("price_quote_per_coin", "1");
    body.pushKV("observed_at", t0);
    auto refused = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &body));
    BOOST_CHECK_GE(refused.status, 400);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(refused), modelnet::HCP_ERR_PRICE_STALE);

    // A refused observation yields no floor at all, and an observation stamped
    // in the future is not treated as fresher truth.
    int64_t floor = 12345;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ReportingFloorAtoms("1", "10", 0, /*observed_at=*/200, /*now=*/100,
                                                   /*max_age=*/1000, 0, floor, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_PRICE_STALE);
    BOOST_CHECK_EQUAL(floor, 0);

    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

// Gap: refusing a stale observation must leave no residue. A rejected plan must
// not consume the replenishment cooldown, turnover, or any balance.
BOOST_AUTO_TEST_CASE(hcp_rem_02_stale_observation_refusal_has_no_side_effects)
{
    auto e = cr11_test::Lab();
    const auto tok = cr11_test::Tok(*e);

    UniValue pol(UniValue::VOBJ);
    pol.pushKV("replenishment_mode", "AUTO");
    pol.pushKV("lifetime_cap_atoms", "1000000");
    auto policy = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok, &pol));
    BOOST_REQUIRE_EQUAL(policy.status, 201);

    const int64_t spent_before = e->Cr11LifetimeSpent();
    const int64_t outstanding_before = e->Cr11Outstanding();
    const int64_t available_before = e->AccountAvailable("account-demo");
    const int64_t held_before = e->AccountHeld("account-demo");

    UniValue stale(UniValue::VOBJ);
    stale.pushKV("required_quote", "1");
    stale.pushKV("price_quote_per_coin", "1");
    stale.pushKV("observed_at", e->Now() - 600'000);
    for (int attempt = 0; attempt < 3; ++attempt) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &stale));
        BOOST_CHECK_GE(r.status, 400);
        BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PRICE_STALE);
        BOOST_CHECK(!cr11_test::Json(r).exists("floor_atoms"));
    }

    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), spent_before);
    BOOST_CHECK_EQUAL(e->Cr11Outstanding(), outstanding_before);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), available_before);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), held_before);

    // Staleness is not sticky and the refusals did not latch the AUTO cooldown:
    // a fresh observation still executes on the first try.
    UniValue good(UniValue::VOBJ);
    good.pushKV("required_quote", "1");
    good.pushKV("price_quote_per_coin", "1");
    good.pushKV("observed_at", e->Now());
    auto ok = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &good));
    BOOST_REQUIRE_EQUAL(ok.status, 201);
    const UniValue plan = cr11_test::Json(ok);
    BOOST_CHECK(!plan["proposal"].get_bool());
    BOOST_CHECK_EQUAL(plan["executed_orders"].getInt<int64_t>(), 1);
    BOOST_CHECK_GE(Num(plan["floor_atoms"]), 1);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

// Gap: pre-pay. A mandate must refuse terms that have not reached the mandate's
// minimum confirmations, must not burn budget doing so, and must still honour
// the same event once the terms confirm.
BOOST_AUTO_TEST_CASE(hcp_rem_03_mandate_refuses_unconfirmed_prepay)
{
    const SubscriptionMandate m = ParsedMandate("mid-prepay", /*minimum_confirmations=*/1);
    BOOST_REQUIRE_EQUAL(m.minimum_confirmations, 1);

    SubscriptionBudget budget;
    std::string err;
    BOOST_REQUIRE_MESSAGE(budget.Bind(m, err), err);

    const auto ev = FundEvent("ev-prepay-1", "mid-prepay");
    SignedTerms unconfirmed = Terms(/*confirmations=*/0);

    BOOST_CHECK(!Evaluate(ev, unconfirmed, m, kMandateNow, err));
    BOOST_CHECK_EQUAL(err, "confirmations");

    // Retrying a pre-pay never accumulates actions, principal, or exposure.
    for (int attempt = 0; attempt < 3; ++attempt) {
        Reservation r;
        BOOST_CHECK(!budget.EvaluateAndReserve(ev, unconfirmed, r, kMandateNow, err));
        BOOST_CHECK_EQUAL(err, "confirmations");
        BOOST_CHECK(r.reservation_id.empty());
    }
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), 0);
    BOOST_CHECK_EQUAL(budget.UsedFees(), 0);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 0);
    BOOST_CHECK_EQUAL(budget.ConcurrentReservations(), 0);
    CheckUnsignedAndZeroSpend(budget.StatusJson());

    // A funding plan over unconfirmed terms stays an unsigned plan. It is never
    // an advance payment.
    const UniValue advance = PrepareFundingPlan(ev, unconfirmed);
    BOOST_CHECK(advance["unsigned"].get_bool());
    CheckUnsignedAndZeroSpend(advance);

    // The refusal is not sticky: the same event settles once the terms confirm,
    // and the result is still unsigned and unbroadcast.
    SignedTerms confirmed = Terms(/*confirmations=*/1);
    Reservation r;
    BOOST_REQUIRE_MESSAGE(budget.EvaluateAndReserve(ev, confirmed, r, kMandateNow, err), err);
    BOOST_CHECK(!r.wallet_signed);
    BOOST_CHECK(!r.broadcast);
    BOOST_CHECK(!r.contains_wallet_material);
    BOOST_CHECK_EQUAL(budget.ActionCount(), 1);
    BOOST_CHECK_EQUAL(budget.UsedPrincipal(), confirmed.principal_atoms);
    CheckUnsignedAndZeroSpend(ReservationToJson(r));
}

// Same pre-pay bar over the helper RPC surface, where a caller controls the
// whole terms object. REJECTED must be the answer and the status must show an
// untouched budget.
BOOST_AUTO_TEST_CASE(hcp_rem_04_mandate_prepay_refused_over_helper_rpc)
{
    SubscriptionStore store;
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(store.Dispatch("createsubscriptionmandate", Arr(MandateJson("mid-rpc-prepay", 1)), result,
                                         code, err, kMandateNow),
                          err);
    BOOST_CHECK_EQUAL(result["mandate_id"].get_str(), "mid-rpc-prepay");

    UniValue req(UniValue::VOBJ);
    req.pushKV("mandate_id", "mid-rpc-prepay");
    req.pushKV("event_id", "ev-rpc-prepay");
    req.pushKV("publisher_id", kPublisher);
    req.pushKV("object_kind", "RELEASE");
    req.pushKV("action", "FUND_WITH_MANDATE");
    req.pushKV("signed_terms", TermsJson(/*confirmations=*/0));

    UniValue refused;
    BOOST_CHECK(!store.Dispatch("reservesubscriptionmandate", Arr(req), refused, code, err, kMandateNow));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK_EQUAL(err, "confirmations");
    BOOST_CHECK(!refused.exists("reservation_id"));

    UniValue status;
    BOOST_REQUIRE(store.Dispatch("getsubscriptionmandate", Arr(req), status, code, err, kMandateNow));
    BOOST_CHECK_EQUAL(status["action_count"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(Num(status["used_principal_atoms"]), 0);
    BOOST_CHECK_EQUAL(Num(status["used_fee_atoms"]), 0);
    CheckUnsignedAndZeroSpend(status);

    // A caller cannot talk its way past the bar by naming the money twice.
    UniValue smuggle = req;
    smuggle.pushKV("confirmations", 1);
    UniValue still_refused;
    BOOST_CHECK(
        !store.Dispatch("reservesubscriptionmandate", Arr(smuggle), still_refused, code, err, kMandateNow));
    BOOST_CHECK_EQUAL(code, "REJECTED");
    BOOST_CHECK_EQUAL(err, "confirmations");

    UniValue accept = req;
    accept.pushKV("signed_terms", TermsJson(/*confirmations=*/1));
    UniValue reserved;
    BOOST_REQUIRE_MESSAGE(
        store.Dispatch("reservesubscriptionmandate", Arr(accept), reserved, code, err, kMandateNow), err);
    BOOST_CHECK(!reserved["reservation_id"].get_str().empty());
    BOOST_CHECK(!reserved["broadcast"].get_bool());
    BOOST_CHECK(!reserved["contains_wallet_material"].get_bool());
    CheckUnsignedAndZeroSpend(reserved);
    BOOST_CHECK_EQUAL(Num(reserved["used_principal_atoms"]), 10);
}

// Honest record of today's behaviour, not a claim of safety: an owner who sets
// minimum_confirmations to 0 gets no pre-pay bar at all. The reservation is
// still unsigned and automatic_spend_atoms is still 0, so the gap is in
// authorization breadth, not in silent spending.
BOOST_AUTO_TEST_CASE(hcp_rem_05_minimum_confirmations_zero_admits_unconfirmed_documents_gap)
{
    const SubscriptionMandate m = ParsedMandate("mid-zero-conf", /*minimum_confirmations=*/0);
    BOOST_REQUIRE_EQUAL(m.minimum_confirmations, 0);

    SubscriptionBudget budget;
    std::string err;
    BOOST_REQUIRE_MESSAGE(budget.Bind(m, err), err);

    const auto ev = FundEvent("ev-zero-conf", "mid-zero-conf");
    const SignedTerms unconfirmed = Terms(/*confirmations=*/0);
    BOOST_CHECK_MESSAGE(Evaluate(ev, unconfirmed, m, kMandateNow, err), err);

    Reservation r;
    BOOST_REQUIRE_MESSAGE(budget.EvaluateAndReserve(ev, unconfirmed, r, kMandateNow, err), err);
    BOOST_CHECK(!r.wallet_signed);
    BOOST_CHECK(!r.broadcast);
    BOOST_CHECK(!r.contains_wallet_material);
    CheckUnsignedAndZeroSpend(ReservationToJson(r));
}

BOOST_AUTO_TEST_SUITE_END()
