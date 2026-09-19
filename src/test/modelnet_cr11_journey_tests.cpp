// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_journey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_j01_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j01");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 250);
}

BOOST_AUTO_TEST_CASE(cr11_j02_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "j02-mandate");
    pol.pushKV("protected_atoms", "400");
    pol.pushKV("lifetime_cap_atoms", "1000000");
    pol.pushKV("replenishment_mode", "SUGGEST");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok, &pol));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_POLICY);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/policies/j02-mandate", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["policy_id"].get_str(), "j02-mandate");
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j02-order");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/allocations/" + aid, tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_ALLOCATION);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["policy_ref"].get_str(), "j02-mandate");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_EXECUTION);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_j03_journey)
{
    auto e = cr11_test::Lab();
    e->Cr11SetFamilyView(true);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "j03");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_FAMILY_VIEW);
}

BOOST_AUTO_TEST_CASE(cr11_j04_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "j04-foundation");
    prog.pushKV("title", "finite-bounty");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESEARCH_PROGRAM);
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent_sponsor_lots"].isTrue());
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/j04-foundation", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["program_id"].get_str(), "j04-foundation");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j04-foundation/memberships", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PROGRAM_MEMBERSHIP);
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent"].isTrue());
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j04-foundation/commitments", tok));
    BOOST_CHECK(cr11_test::Json(r)["prepared"].isTrue());
    BOOST_CHECK(!cr11_test::Json(r)["executed"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_j05_journey)
{
    auto e = hcp_test::Lab(false);
    BOOST_CHECK(e->Cfg().walletless);
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr11_j06_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_EXTENSION);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("position_id", "j06-resident");
    pos.pushKV("recipe_id", std::string(96, '6'));
    pos.pushKV("lock_id", "lock-j06-lan");
    pos.pushKV("lifecycle", "LOCKED");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &pos));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPABILITY_POSITION);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/positions/j06-resident", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["recipe_id"].get_str(), std::string(96, '6'));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["lock_id"].get_str(), "lock-j06-lan");
}

BOOST_AUTO_TEST_CASE(cr11_j07_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue sug(UniValue::VOBJ);
    sug.pushKV("required_quote", "1");
    sug.pushKV("price_quote_per_coin", "1");
    sug.pushKV("observed_at", e->Now());
    sug.pushKV("max_age", static_cast<int64_t>(100000));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &sug));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["executed_orders"].getInt<int64_t>(), 0);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "j07-auto");
    pol.pushKV("replenishment_mode", "AUTO");
    pol.pushKV("lifetime_cap_atoms", "1000000");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok, &pol));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/policies/j07-auto", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["replenishment_mode"].get_str(), "AUTO");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &sug));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["executed_orders"].getInt<int64_t>(), 1);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/replenishment/plans", tok, &sug));
    BOOST_CHECK_EQUAL(r.status, 409);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), "REPLENISH_COOLDOWN");
}

BOOST_AUTO_TEST_CASE(cr11_j08_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "j08-committee");
    rule.pushKV("distinct_person_quorum", static_cast<int64_t>(2));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok, &rule));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approval-rules/j08-committee", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_RULE);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j08-packet");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "j08-apr");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "j08-committee");
    req.pushKV("initiator_person_id", "person-initiator");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &req));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/j08-apr", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_REQUEST);
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "alice-session");
    dec.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j08-apr/decisions", tok, &dec));
    BOOST_CHECK_EQUAL(r.status, 201);
    e->Cr11ExpirePerson("person-b");
    UniValue decb(UniValue::VOBJ);
    decb.pushKV("actor", "bob-session");
    decb.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j08-apr/decisions", tok, &decb));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);
    UniValue changed(UniValue::VOBJ);
    changed.pushKV("client_operation_id", "j08-packet");
    changed.pushKV("maximum_exposure", "11");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &changed));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CONFLICT);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
}

BOOST_AUTO_TEST_CASE(cr11_j09_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue cyclic(UniValue::VOBJ);
    cyclic.pushKV("client_operation_id", "j09-cycle");
    cyclic.pushKV("maximum_exposure", "10");
    UniValue legs(UniValue::VARR);
    UniValue a(UniValue::VOBJ);
    a.pushKV("leg_id", "J09A");
    a.pushKV("kind", "FINANCIAL");
    UniValue da(UniValue::VARR);
    da.push_back("J09B");
    a.pushKV("depends_on", da);
    UniValue b(UniValue::VOBJ);
    b.pushKV("leg_id", "J09B");
    b.pushKV("kind", "FINANCIAL");
    UniValue db(UniValue::VARR);
    db.push_back("J09A");
    b.pushKV("depends_on", db);
    legs.push_back(a);
    legs.push_back(b);
    cyclic.pushKV("legs", legs);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &cyclic));
    BOOST_CHECK_EQUAL(r.status, 400);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_GRAPH_CYCLE);
    UniValue acyclic(UniValue::VOBJ);
    acyclic.pushKV("client_operation_id", "j09-resume");
    acyclic.pushKV("maximum_exposure", "10");
    UniValue oklegs(UniValue::VARR);
    UniValue f(UniValue::VOBJ);
    f.pushKV("leg_id", "FUND");
    f.pushKV("kind", "FINANCIAL");
    UniValue loc(UniValue::VOBJ);
    loc.pushKV("leg_id", "LOCAL");
    loc.pushKV("kind", "LOCAL");
    UniValue dl(UniValue::VARR);
    dl.push_back("FUND");
    loc.pushKV("depends_on", dl);
    oklegs.push_back(f);
    oklegs.push_back(loc);
    acyclic.pushKV("legs", oklegs);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &acyclic));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/allocations/" + aid, tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_ALLOCATION);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["execution_order"][0].get_str(), "FUND");
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_CASE(cr11_j10_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j10-broadcast");
    alloc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["body"]["execution_id"].get_str();
    BOOST_CHECK_EQUAL(xid, e->Cr11LastExecutionId());
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/executions/" + xid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_EXECUTION);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["state"].get_str(), "HELD");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["allocation_ref"].get_str(), aid);
}

BOOST_AUTO_TEST_CASE(cr11_j11_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "j11-cosponsor");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/j11-cosponsor", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent_sponsor_lots"].isTrue());
    UniValue ma(UniValue::VOBJ);
    ma.pushKV("legal_entity_id", "le-alpha");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j11-cosponsor/memberships", tok, &ma));
    const std::string lot_a = cr11_test::Json(r)["body"]["lot_id"].get_str();
    UniValue mb(UniValue::VOBJ);
    mb.pushKV("legal_entity_id", "le-beta");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j11-cosponsor/memberships", tok, &mb));
    const std::string lot_b = cr11_test::Json(r)["body"]["lot_id"].get_str();
    UniValue mc(UniValue::VOBJ);
    mc.pushKV("legal_entity_id", "le-gamma");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j11-cosponsor/memberships", tok, &mc));
    const std::string lot_c = cr11_test::Json(r)["body"]["lot_id"].get_str();
    BOOST_CHECK(lot_a != lot_b && lot_b != lot_c && lot_a != lot_c);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["member_entity"].get_str(), "le-gamma");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/j11-cosponsor/commitments", tok));
    BOOST_CHECK(!cr11_test::Json(r)["executed"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_j12_journey)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10);
    e->Cr11SetRefundReplenish(false);
    auto tok = cr11_test::Tok(*e);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j12-refund");
    alloc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = e->Cr11LastExecutionId();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/executions/" + xid, tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["state"].get_str(), "CANCELED");
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 10);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
    UniValue again(UniValue::VOBJ);
    again.pushKV("client_operation_id", "j12-renew");
    again.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &again));
    const std::string aid2 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_j13_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("plan_id", "j13-hw");
    plan.pushKV("objective", "approved-hardware");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/plans/j13-hw", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_PLAN);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PRODUCT_OFFER);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/products/prod-demo/referral", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK(cr11_test::Json(r)["not_a_debit"].isTrue());
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK(cr11_test::Json(r)["referral_id"].get_str().find("ref-") == 0);
}

BOOST_AUTO_TEST_CASE(cr11_j14_journey)
{
    auto e = cr11_test::Lab();
    e->Cr11SetEncumbered(700);
    auto tok = cr11_test::Tok(*e);
    UniValue port(UniValue::VOBJ);
    port.pushKV("portfolio_id", "j14-collateral");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &port));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/j14-collateral", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PORTFOLIO);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/j14-collateral/snapshot", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_SNAPSHOT);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["allocation_capacity_atoms"].get_str(), "0");
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j14-double");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_j15_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue usd(UniValue::VOBJ);
    usd.pushKV("portfolio_id", "j15-usd");
    usd.pushKV("reporting_currency", "USD");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &usd));
    BOOST_CHECK_EQUAL(r.status, 201);
    UniValue jpy(UniValue::VOBJ);
    jpy.pushKV("portfolio_id", "j15-jpy");
    jpy.pushKV("reporting_currency", "JPY");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &jpy));
    BOOST_CHECK_EQUAL(r.status, 201);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("forecast_as_actual", true);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan));
    BOOST_CHECK_EQUAL(r.status, 400);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_REPORT);
    BOOST_CHECK(cr11_test::Json(r)["body"]["nav_merged"].isFalse());
    BOOST_CHECK(cr11_test::Json(r)["body"]["fx_dated"].isTrue());
    BOOST_CHECK(cr11_test::Json(r)["body"]["assumptions_separate_from_actuals"].isTrue());
    const std::string rid = cr11_test::Json(r)["body"]["report_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/reports/" + rid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["export_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + xid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["export_id"].get_str(), xid);
}

BOOST_AUTO_TEST_CASE(cr11_j16_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue link(UniValue::VOBJ);
    link.pushKV("link_id", "j16-adviser");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok, &link));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_ENTITY_LINK);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/entities/links/j16-adviser", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["status"].get_str(), "ACTIVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["export_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links/j16-adviser/revoke", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["status"].get_str(), "REVOKED");
    UniValue p(UniValue::VOBJ);
    p.pushKV("via_link", "j16-adviser");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &p));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_ENTITY_SCOPE);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + xid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(cr11_test::Json(r)["excluded_unauthorized"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_j17_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("position_id", "j17-local");
    pos.pushKV("lock_id", "lock-j17");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &pos));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/positions/j17-local", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["position_id"].get_str(), "j17-local");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["export_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + xid, tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["export_id"].get_str(), xid);
    e->Cr11MarkCrossCexAction("j17-cex-a");
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j17-replay");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("cross_cex_action_id", "j17-cex-a");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok, &ex));
    BOOST_CHECK_EQUAL(r.status, 409);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CROSS_CEX);
}

BOOST_AUTO_TEST_CASE(cr11_j18_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue wl(UniValue::VOBJ);
    wl.pushKV("workload_id", "j18-browser");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok, &wl));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_WORKLOAD);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/workloads/j18-browser", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["workload_id"].get_str(), "j18-browser");
    UniValue cmp(UniValue::VOBJ);
    cmp.pushKV("comparison_id", "j18-tco");
    cmp.pushKV("workload_ref", "j18-browser");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &cmp));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/comparisons/j18-tco", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_TCO);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "j18-apr");
    apr.pushKV("initiator_person_id", "person-initiator");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &apr));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/j18-apr", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_REQUEST);
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "alice-session");
    dec.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j18-apr/decisions", tok, &dec));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_DECISION);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["person"].get_str(), "person-a");
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/j18-apr/decisions", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["items"].size(), 1);
}

BOOST_AUTO_TEST_CASE(cr11_j19_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue v4(UniValue::VOBJ);
    v4.pushKV("package_core_version", 4);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &v4));
    BOOST_CHECK_EQUAL(r.status, 400);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CORE_V4);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_EXTENSION);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_j20_journey)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK(cr11_test::Json(r)["cognitive_reserve"].isTrue());
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
