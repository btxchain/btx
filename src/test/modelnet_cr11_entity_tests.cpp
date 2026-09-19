// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_entity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_entity_01_group_view_not_debit)
{
    auto e = cr11_test::Lab();
    e->Cr11SetFamilyView(true);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "fam-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_FAMILY_VIEW);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_entity_02_family_segregation)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetSiblingFunds(500);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), modelnet::Cr11Capacity(500, 400, 250));
}

BOOST_AUTO_TEST_CASE(cr11_entity_03_adviser_draft_only)
{
    auto e = cr11_test::Lab();
    auto tok = hcp_test::Token(*e, {"capital:prepare", "capital:read"});
    UniValue body(UniValue::VOBJ);
    body.pushKV("plan_id", "draft-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/x/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr11_entity_04_forged_request_account)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("legal_entity_id", "le-other");
    body.pushKV("client_operation_id", "forge-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_ENTITY_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr11_entity_05_self_escalation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("person_id", "account-demo");
    body.pushKV("role", "policies:admin");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/roles", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 403);
}

BOOST_AUTO_TEST_CASE(cr11_entity_06_membership_expiry)
{
    auto e = cr11_test::Lab();
    e->Cr11ExpirePerson("person-a");
    auto tok = cr11_test::Tok(*e);
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "rule-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok, &rule));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue req(UniValue::VOBJ);
    req.pushKV("rule_ref", "rule-1");
    req.pushKV("initiator_person_id", "person-initiator");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &req));
    const std::string rid = cr11_test::Json(r)["body"]["request_id"].get_str();
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "alice-session");
    dec.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/" + rid + "/decisions", tok, &dec));
    BOOST_CHECK_EQUAL(r.status, 403);
}

BOOST_AUTO_TEST_CASE(cr11_entity_07_scoped_export)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_CHECK(cr11_test::Json(r)["excluded_unauthorized"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_entity_08_cross_entity_legs)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    UniValue legs(UniValue::VARR);
    UniValue a(UniValue::VOBJ);
    a.pushKV("leg_id", "L1");
    a.pushKV("kind", "FINANCIAL");
    UniValue c(UniValue::VOBJ);
    c.pushKV("leg_id", "L2");
    c.pushKV("kind", "FINANCIAL");
    legs.push_back(a);
    legs.push_back(c);
    body.pushKV("legs", legs);
    body.pushKV("client_operation_id", "xent-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
}

BOOST_AUTO_TEST_CASE(cr11_entity_09_independent_currencies)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue usd(UniValue::VOBJ);
    usd.pushKV("portfolio_id", "usd");
    usd.pushKV("reporting_currency", "USD");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &usd));
    BOOST_CHECK_EQUAL(r.status, 201);
    UniValue jpy(UniValue::VOBJ);
    jpy.pushKV("portfolio_id", "jpy");
    jpy.pushKV("reporting_currency", "JPY");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &jpy));
    BOOST_CHECK_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_CHECK(cr11_test::Json(r)["body"]["fx_dated"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr11_entity_10_relationship_revocation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok));
    const std::string id = cr11_test::Json(r)["body"]["link_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links/" + id + "/revoke", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    UniValue p(UniValue::VOBJ);
    p.pushKV("via_link", id);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &p));
    BOOST_CHECK_EQUAL(r.status, 403);
}

BOOST_AUTO_TEST_SUITE_END()
