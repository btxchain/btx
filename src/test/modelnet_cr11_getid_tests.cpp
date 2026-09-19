// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native GET-by-id coverage for previously unhit CR11 operations.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_getid_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_getid_entity_link)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("parent_entity_id", "account-demo");
    body.pushKV("child_entity_id", "le-child");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["link_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/entities/links/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_ENTITY_LINK);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["link_id"].get_str(), id);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/entities/links/missing", tok));
    BOOST_CHECK_EQUAL(r.status, 404);
}

BOOST_AUTO_TEST_CASE(cr11_getid_portfolio)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["portfolio_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["portfolio_id"].get_str(), id);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/" + id + "/snapshot", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_SNAPSHOT);
}

BOOST_AUTO_TEST_CASE(cr11_getid_reserve_policy)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/policies", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["policy_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/policies/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["policy_id"].get_str(), id);
}

BOOST_AUTO_TEST_CASE(cr11_getid_workload)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["workload_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/workloads/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_WORKLOAD);
}

BOOST_AUTO_TEST_CASE(cr11_getid_tco_comparison)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("annual_tasks", "20000000");
    body.pushKV("service_per_task", "0.01");
    body.pushKV("years", 3);
    body.pushKV("upfront", "50000");
    body.pushKV("annual_local", "65000");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["comparison_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/comparisons/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_TCO);
}

BOOST_AUTO_TEST_CASE(cr11_getid_capital_plan)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["plan_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/plans/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_PLAN);
}

BOOST_AUTO_TEST_CASE(cr11_getid_allocation_plan)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "getid-alloc");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/allocations/" + id, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_ALLOCATION);
}

BOOST_AUTO_TEST_CASE(cr11_getid_approval_rule_request_decisions)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string rid = cr11_test::Json(r)["body"]["rule_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approval-rules/" + rid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_RULE);
    UniValue req(UniValue::VOBJ);
    req.pushKV("rule_ref", rid);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &req));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["request_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/" + aid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_APPROVAL_REQUEST);
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "alice-session");
    dec.pushKV("decision", "APPROVE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/" + aid + "/decisions", tok, &dec));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/" + aid + "/decisions", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(cr11_test::Json(r)["items"].isArray());
    BOOST_CHECK_GE(cr11_test::Json(r)["items"].size(), 1);
}

BOOST_AUTO_TEST_CASE(cr11_getid_capital_execution)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "getid-exec");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + id + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["body"]["execution_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/executions/" + xid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["execution_id"].get_str(), xid);
    BOOST_CHECK(cr11_test::Json(r)["body"]["runtime_ready"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr11_getid_capital_export_program_product)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string eid = cr11_test::Json(r)["export_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + eid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["export_id"].get_str(), eid);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/missing", tok));
    BOOST_CHECK_EQUAL(r.status, 404);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string pid = cr11_test::Json(r)["body"]["program_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/" + pid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESEARCH_PROGRAM);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PRODUCT_OFFER);
}

BOOST_AUTO_TEST_CASE(cr11_getid_program_and_rule_are_account_scoped)
{
    auto e = cr11_test::Lab();
    const auto tok_a = cr11_test::Tok(*e);
    e->PutAccount("account-b", 777);
    const std::string ver = "pkce-verifier-account-b-getid";
    const std::string ch = e->LabCreatePkceChallenge(ver);
    const std::string code =
        e->LabAuthorize("account-b", "client-demo", "https://app.example/cb", "state-b", ch, cr11_test::Scopes());
    UniValue tok;
    std::string err;
    BOOST_REQUIRE(e->LabToken(code, ver, "https://app.example/cb", e->LabJkt(), "", tok, err));
    const std::string tok_b = tok["access_token"].get_str();

    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog-owned-a");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok_a, &prog));
    BOOST_REQUIRE_EQUAL(created.status, 201);

    auto foreign = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog-owned-a", tok_b));
    BOOST_CHECK_EQUAL(foreign.status, 404);

    auto owner = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog-owned-a", tok_a));
    BOOST_REQUIRE_EQUAL(owner.status, 200);

    auto rule = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok_a));
    BOOST_REQUIRE_EQUAL(rule.status, 201);
    const std::string rid = cr11_test::Json(rule)["body"]["rule_id"].get_str();
    auto foreign_rule = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approval-rules/" + rid, tok_b));
    BOOST_CHECK_EQUAL(foreign_rule.status, 404);
    auto owner_rule = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approval-rules/" + rid, tok_a));
    BOOST_REQUIRE_EQUAL(owner_rule.status, 200);
}

BOOST_AUTO_TEST_SUITE_END()
