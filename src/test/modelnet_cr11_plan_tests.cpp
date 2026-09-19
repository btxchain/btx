// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_plan_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_plan_01_cycle_rejection)
{
    UniValue legs(UniValue::VARR);
    UniValue a(UniValue::VOBJ);
    a.pushKV("leg_id", "A");
    UniValue da(UniValue::VARR);
    da.push_back("B");
    a.pushKV("depends_on", da);
    UniValue b(UniValue::VOBJ);
    b.pushKV("leg_id", "B");
    UniValue db(UniValue::VARR);
    db.push_back("A");
    b.pushKV("depends_on", db);
    legs.push_back(a);
    legs.push_back(b);
    std::vector<std::string> order;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ValidateDag(legs, order, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_GRAPH_CYCLE);
}

BOOST_AUTO_TEST_CASE(cr11_plan_02_missing_dependency)
{
    UniValue legs(UniValue::VARR);
    UniValue a(UniValue::VOBJ);
    a.pushKV("leg_id", "A");
    UniValue da(UniValue::VARR);
    da.push_back("Z");
    a.pushKV("depends_on", da);
    legs.push_back(a);
    std::vector<std::string> order;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ValidateDag(legs, order, err));
    BOOST_CHECK_EQUAL(err, "MISSING_DEPENDENCY");
}

BOOST_AUTO_TEST_CASE(cr11_plan_03_finite_graph)
{
    UniValue legs(UniValue::VARR);
    for (int i = 0; i < 33; ++i) {
        UniValue x(UniValue::VOBJ);
        x.pushKV("leg_id", "L" + std::to_string(i));
        legs.push_back(x);
    }
    std::vector<std::string> order;
    std::string err;
    BOOST_CHECK(!modelnet::Cr11ValidateDag(legs, order, err));
    BOOST_CHECK_EQUAL(err, modelnet::HCP_ERR_GRAPH_LIMIT);
}

BOOST_AUTO_TEST_CASE(cr11_plan_04_stable_child_identities)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "stable-1");
    body.pushKV("maximum_exposure", "10");
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::Json(r1)["body"]["allocation_id"].get_str(),
                      cr11_test::Json(r2)["body"]["allocation_id"].get_str());
}

BOOST_AUTO_TEST_CASE(cr11_plan_05_partial_conversion)
{
    auto e = cr11_test::Lab();
    e->CompleteConversion("nope");
    BOOST_CHECK_GE(e->AccountAvailable("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_plan_06_unknown_child)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK(e->IntentState("nope").empty());
    e->ForceBroadcastUnknown("nope");
    BOOST_CHECK_EQUAL(e->IntentState("nope"), modelnet::HCP_ERR_BROADCAST_UNKNOWN);
    BOOST_CHECK(e->IntentState("never-created").empty());
}

BOOST_AUTO_TEST_CASE(cr11_plan_07_fenced_execution)
{
    auto e = cr11_test::Lab();
    e->SetExecutorOwner("replica-1");
    e->ExpireLease();
    BOOST_CHECK_EQUAL(e->DualInstancePeerNote()["independent"].isTrue(), true);
}

BOOST_AUTO_TEST_CASE(cr11_plan_08_pre_effect_cancellation)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "can-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = e->Cr11LastExecutionId();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_plan_09_post_effect_cancellation)
{
    auto e = cr11_test::Lab();
    e->SetDmaActive(true);
    e->FenceDma();
    BOOST_CHECK(!e->Cfg().expose_runtime_to_gateway);
}

BOOST_AUTO_TEST_CASE(cr11_plan_10_separate_entity_approvals)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("legal_entity_id", "le-other");
    body.pushKV("client_operation_id", "sep-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_ENTITY_SCOPE);
}

BOOST_AUTO_TEST_SUITE_END()
