// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_instruction_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_instruction_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->AccountAvailable("account-demo");
    UniValue a(UniValue::VOBJ);
    a.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    auto t = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + cr12_test::Body(r)["instruction_id"].get_str() + "/translate", tok));
    const std::string pid = cr12_test::Body(t)["draft_plan_id"].get_str();
    BOOST_CHECK(!pid.empty());
    BOOST_CHECK(cr12_test::Body(t)["no_reservation"].isTrue());
    BOOST_CHECK(!cr12_test::Body(t)["execute"].isTrue());
    auto plan = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/plans/" + pid, tok));
    BOOST_CHECK_EQUAL(plan.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(plan), modelnet::HCP_TYPE_CAPITAL_PLAN);
    BOOST_CHECK_EQUAL(cr12_test::Body(plan)["state"].get_str(), "DRAFT");
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), before);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("legal_entity_id", "other-le");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a))),
                      modelnet::HCP_ERR_ENTITY_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("stale_projection", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a))),
                      modelnet::HCP_ERR_STALE_SOURCE);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("instruction_id", "ins-1");
    a.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("instruction_id", "ins-1");
    b.pushKV("requested_action", "DRAFT_RESEARCH_COMMITMENT");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &b))),
                      modelnet::HCP_ERR_CONFLICT);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("instruction_id", "ins-eq");
    a.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    const std::string id = cr12_test::Body(r)["instruction_id"].get_str();
    auto t1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + id + "/translate", tok));
    auto t2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + id + "/translate", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(t1)["draft_plan_id"].get_str(), cr12_test::Body(t2)["draft_plan_id"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_instruction_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    auto t = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + cr12_test::Body(r)["instruction_id"].get_str() + "/translate", tok));
    const std::string aid = cr12_test::Body(t)["draft_allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "ins06-rule");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok, &rule)).status, 201);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "ins06-req");
    apr.pushKV("allocation_ref", aid);
    apr.pushKV("rule_ref", "ins06-rule");
    apr.pushKV("initiator_person_id", "person-initiator");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &apr)).status, 201);
    auto ex = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(ex), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    auto t = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + cr12_test::Body(r)["instruction_id"].get_str() + "/translate", tok));
    const std::string aid = cr12_test::Body(t)["draft_allocation_id"].get_str();
    auto analytics = cr12_test::Tok(*e, cr12_test::AnalyticsScopes());
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", analytics))),
                      modelnet::HCP_ERR_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("requested_action", "DRAFT_CAPABILITY_ACQUISITION");
    a.pushKV("desktop_context", true);
    BOOST_CHECK(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a)))["execute"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_instruction_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("remote_inference", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a))),
                      modelnet::HCP_ERR_REMOTE_INFERENCE);
}

BOOST_AUTO_TEST_CASE(cr12_instruction_10)
{
    auto e = cr12_test::Lab();
    const std::string orig = e->Cfg().provider_id;
    e->SetPendingUnknownOn(orig, "intent-child");
    auto sw = e->SwitchProvider("provider-analytics-b");
    BOOST_CHECK(sw["finance_replayed"].isFalse());
    BOOST_CHECK_EQUAL(sw["unresolved_on_old"].get_str(), "intent-child");
    BOOST_CHECK_EQUAL(e->ExportPublic(false)["unresolved_finance_provider"].get_str(), orig);
}

BOOST_AUTO_TEST_SUITE_END()
