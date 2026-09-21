// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_metric_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_metric_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK(modelnet::Crl12MetricEligible("AUM", "MANAGED", "FINANCIAL"));
    BOOST_CHECK(!modelnet::Crl12MetricEligible("AUM", "NONE", "FINANCIAL"));
    UniValue m(UniValue::VOBJ);
    m.pushKV("observation_id", "pos-m");
    m.pushKV("mandate", "MANAGED");
    m.pushKV("source", "src-a");
    m.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &m)).status, 201);
    UniValue u(UniValue::VOBJ);
    u.pushKV("observation_id", "pos-u");
    u.pushKV("mandate", "NONE");
    u.pushKV("source", "src-b");
    u.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &u)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_metric_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue c(UniValue::VOBJ);
    c.pushKV("observation_id", "pos-c");
    c.pushKV("mandate", "CUSTODY");
    c.pushKV("source", "src-a");
    c.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &c)).status, 201);
    UniValue v(UniValue::VOBJ);
    v.pushKV("observation_id", "pos-v");
    v.pushKV("mandate", "NONE");
    v.pushKV("source", "src-b");
    v.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &v)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUC");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_metric_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("mandate", "ADMIN");
    a.pushKV("source", "src-a");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue aua(UniValue::VOBJ);
    aua.pushKV("metric_kind", "AUA");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &aua)))["metric_results"][0]
                          ["eligible_count"]
                              .getInt<int64_t>(),
                      1);
    UniValue aum(UniValue::VOBJ);
    aum.pushKV("metric_kind", "AUM");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &aum)))["metric_results"][0]
                          ["eligible_count"]
                              .getInt<int64_t>(),
                      0);
}

BOOST_AUTO_TEST_CASE(cr12_metric_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK(!modelnet::Crl12MetricEligible("AUM", "MANAGED", "CAPABILITY"));
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("asset_kind", "CAPABILITY");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 0);
    BOOST_CHECK(!cr12_test::Body(r).exists("invented_aum"));
}

BOOST_AUTO_TEST_CASE(cr12_metric_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue asset(UniValue::VOBJ);
    asset.pushKV("kind", "CAPABILITY");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &asset)).status, 201);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("asset_kind", "CAPABILITY");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue links(UniValue::VARR);
    for (int i = 0; i < 20; ++i) {
        UniValue edge(UniValue::VOBJ);
        edge.pushKV("parent", "recipe");
        edge.pushKV("child", "device-" + std::to_string(i));
        edge.pushKV("kind", "OPERATIONAL");
        links.push_back(edge);
    }
    UniValue exp(UniValue::VOBJ);
    exp.pushKV("links", links);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &exp)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "CAPABILITY_COUNT");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_metric_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue m(UniValue::VOBJ);
    m.pushKV("observation_id", "pos-ov-m");
    m.pushKV("mandate", "MANAGED");
    m.pushKV("beneficial_id", "same");
    m.pushKV("source", "src-a");
    m.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &m)).status, 201);
    UniValue c(UniValue::VOBJ);
    c.pushKV("observation_id", "pos-ov-c");
    c.pushKV("mandate", "CUSTODY");
    c.pushKV("beneficial_id", "same");
    c.pushKV("source", "src-b");
    c.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &c)).status, 201);
    UniValue aum(UniValue::VOBJ);
    aum.pushKV("metric_kind", "AUM");
    auto ra = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &aum));
    UniValue auc(UniValue::VOBJ);
    auc.pushKV("metric_kind", "AUC");
    auto rc = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &auc));
    BOOST_CHECK(cr12_test::Body(ra)["metric_results"][0]["no_grand_total"].isTrue());
    BOOST_CHECK(cr12_test::Body(rc)["metric_results"][0]["no_grand_total"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_metric_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue cost(UniValue::VOBJ);
    cost.pushKV("metric_kind", "ACTUAL_COST");
    cost.pushKV("basis", "COST");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/metrics", tok, &cost)).status, 201);
    UniValue mkt(UniValue::VOBJ);
    mkt.pushKV("metric_kind", "AUM");
    mkt.pushKV("basis", "MARKET");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/metrics", tok, &mkt)).status, 201);
    BOOST_CHECK(modelnet::Crl12MetricEligible("ACTUAL_COST", "MANAGED", "FINANCIAL"));
    BOOST_CHECK(!modelnet::Crl12MetricEligible("ACTUAL_COST", "CUSTODY", "FINANCIAL"));
    auto listed = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/metrics", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(listed)["items"].size(), 2);
}

BOOST_AUTO_TEST_CASE(cr12_metric_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["complete"].isFalse());
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 0);
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["value"].isNull());
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["status"].get_str(), "UNAVAILABLE");
}

BOOST_AUTO_TEST_CASE(cr12_metric_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("mandate", "MANAGED");
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("mandate", "MANAGED");
    b.pushKV("source", "src-a");
    b.pushKV("generation", "1");
    b.pushKV("sequence", "2");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &b)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(r)["status"].get_str() != "COMPLETE");
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["complete"].isFalse());
    BOOST_CHECK(cr12_test::Body(r)["reconciliation_refs"].size() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_metric_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue ext(UniValue::VOBJ);
    ext.pushKV("observation_id", "pos-inflow");
    ext.pushKV("mandate", "MANAGED");
    ext.pushKV("source", "external");
    ext.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &ext)).status, 201);
    UniValue intern(UniValue::VOBJ);
    intern.pushKV("observation_id", "pos-internal");
    intern.pushKV("mandate", "NONE");
    intern.pushKV("source", "internal");
    intern.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &intern)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
