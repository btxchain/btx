// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_projection_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_projection_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "3");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("source", "src-b");
    b.pushKV("generation", "1");
    b.pushKV("sequence", "7");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &b)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["watermarks"].isArray());
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["watermarks"].size(), 2);
}

BOOST_AUTO_TEST_CASE(cr12_projection_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("observation_id", "pos-pin");
    a.pushKV("source", "src-a");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue p(UniValue::VOBJ);
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    const std::string id = cr12_test::Body(pr)["projection_id"].get_str();
    BOOST_CHECK_EQUAL(cr12_test::Body(pr)["position_refs"].size(), 1);
    UniValue extra(UniValue::VOBJ);
    extra.pushKV("observation_id", "pos-later");
    extra.pushKV("source", "src-a");
    extra.pushKV("sequence", "1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &extra)).status, 201);
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/" + id, tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["position_refs"].size(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_projection_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    const std::string id = cr12_test::Body(pr)["projection_id"].get_str();
    auto req = hcp_test::AuthReq(*e, "GET", "/institutional/projections/" + id, tok);
    req.query = "cursor_tenant=account-b";
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(req)), modelnet::HCP_ERR_ENTITY_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr12_projection_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("filter", "aum");
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    const std::string id = cr12_test::Body(pr)["projection_id"].get_str();
    auto req = hcp_test::AuthReq(*e, "GET", "/institutional/projections/" + id, tok);
    req.query = "filter=auc";
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(req)), modelnet::HCP_ERR_CURSOR_MISMATCH);
}

BOOST_AUTO_TEST_CASE(cr12_projection_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("policy_id", "pol-hist");
    p.pushKV("as_of", std::to_string(e->Now()));
    p.pushKV("observed_cutoff", std::to_string(e->Now()));
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["as_of"].get_str(), cr12_test::Body(b)["as_of"].get_str());
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["observed_cutoff"].get_str(), cr12_test::Body(b)["observed_cutoff"].get_str());
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["policy_id"].get_str(), cr12_test::Body(b)["policy_id"].get_str());
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["position_refs"].size(), cr12_test::Body(b)["position_refs"].size());
}

BOOST_AUTO_TEST_CASE(cr12_projection_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("mandate", "MANAGED");
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue gap(UniValue::VOBJ);
    gap.pushKV("mandate", "MANAGED");
    gap.pushKV("source", "src-a");
    gap.pushKV("generation", "1");
    gap.pushKV("sequence", "2");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &gap)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "PARTIAL");
    BOOST_CHECK(cr12_test::Body(r)["reconciliation_refs"].size() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_projection_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Crl12LoadSynthetic(100000, "account-demo", "MANAGED"), 100000);
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 100000);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(pr.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(pr)["position_refs"].size(), 100000);
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("projection_id", cr12_test::Body(pr)["projection_id"].get_str());
    auto er = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &ex));
    BOOST_CHECK_EQUAL(er.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(er)["total_rows"].getInt<int64_t>(), 100000);
}

BOOST_AUTO_TEST_CASE(cr12_projection_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t avail = e->AccountAvailable("account-demo");
    const size_t intents = e->IntentCount();
    UniValue p(UniValue::VOBJ);
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(pr)["no_finance_intent"].isTrue());
    UniValue scn(UniValue::VOBJ);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &scn)).status, 201);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), avail);
    BOOST_CHECK_EQUAL(e->IntentCount(), intents);
}

BOOST_AUTO_TEST_CASE(cr12_projection_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(r)["local_inventory"].isNull());
    BOOST_CHECK(!cr12_test::Body(r).exists("memory_address"));
}

BOOST_AUTO_TEST_CASE(cr12_projection_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue oldp(UniValue::VOBJ);
    oldp.pushKV("policy_id", "pol-old");
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &oldp));
    const std::string old_id = cr12_test::Body(a)["projection_id"].get_str();
    UniValue newp(UniValue::VOBJ);
    newp.pushKV("policy_id", "pol-new");
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &newp));
    BOOST_CHECK_EQUAL(cr12_test::Body(b)["policy_id"].get_str(), "pol-new");
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/" + old_id, tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["policy_id"].get_str(), "pol-old");
}

BOOST_AUTO_TEST_SUITE_END()
