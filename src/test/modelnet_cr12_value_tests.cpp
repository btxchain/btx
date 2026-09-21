// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_value_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_value_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "0");
    val.pushKV("purpose", "MARKET_VALUE");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["value"].get_str(), "0");
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["status"].get_str() != "UNAVAILABLE");
}

BOOST_AUTO_TEST_CASE(cr12_value_02)
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
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["status"].get_str(), "UNAVAILABLE");
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["partial"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_value_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "10");
    val.pushKV("status", "STALE");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(r)["status"].get_str() != "COMPLETE");
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["complete"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_value_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "999");
    val.pushKV("purpose", "REPLACEMENT_SCENARIO");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "FINANCIAL_NAV");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["status"].get_str(), "UNAVAILABLE");
}

BOOST_AUTO_TEST_CASE(cr12_value_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("quantity", "100");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "50");
    val.pushKV("whole_position", true);
    auto vr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val));
    BOOST_CHECK(cr12_test::Body(vr)["whole_position"].isTrue());
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_value_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "10");
    val.pushKV("currency", "USD");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("report_currency", "EUR");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["metric_results"][0]["status"].get_str(), "UNAVAILABLE");
}

BOOST_AUTO_TEST_CASE(cr12_value_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    std::string err;
    BOOST_CHECK(modelnet::Crl12FiniteDecimal("1.2500", err));
    BOOST_CHECK(modelnet::Crl12FiniteDecimal("100", err));
    std::string sum;
    BOOST_CHECK(modelnet::Crl12AddDecimal("1.2500", "2.75", sum, err));
    BOOST_CHECK_EQUAL(sum, "4");
    BOOST_CHECK(modelnet::Crl12AddDecimal("1234.56", "0", sum, err));
    BOOST_CHECK_EQUAL(sum, "1234.56");
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "1.2500");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["value"].get_str(), "1.2500");
}

BOOST_AUTO_TEST_CASE(cr12_value_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue nanv(UniValue::VOBJ);
    nanv.pushKV("value", "NaN");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &nanv))),
                      modelnet::HCP_ERR_NONFINITE);
    UniValue inf(UniValue::VOBJ);
    inf.pushKV("value", "inf");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &inf))),
                      modelnet::HCP_ERR_NONFINITE);
    UniValue neg(UniValue::VOBJ);
    neg.pushKV("value", "-1");
    neg.pushKV("purpose", "MARKET_VALUE");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &neg))),
                      modelnet::HCP_ERR_NONFINITE);
}

BOOST_AUTO_TEST_CASE(cr12_value_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("mandate", "MANAGED");
    pos.pushKV("source", "src-a");
    pos.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
    UniValue v1(UniValue::VOBJ);
    v1.pushKV("value", "10");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &v1)).status, 201);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("as_of", std::to_string(e->Now()));
    p.pushKV("observed_cutoff", std::to_string(e->Now()));
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    UniValue v2(UniValue::VOBJ);
    v2.pushKV("value", "11");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &v2)).status, 201);
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["as_of"].get_str(), cr12_test::Body(b)["as_of"].get_str());
    BOOST_CHECK_EQUAL(cr12_test::Body(a)["metric_kind"].get_str(), cr12_test::Body(b)["metric_kind"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_value_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t avail = e->AccountAvailable("account-demo");
    const size_t intents = e->IntentCount();
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "42");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue p(UniValue::VOBJ);
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(cr12_test::Body(pr)["no_finance_intent"].isTrue());
    UniValue ins(UniValue::VOBJ);
    auto ir = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins));
    BOOST_REQUIRE_EQUAL(ir.status, 201);
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/" + cr12_test::Body(ir)["instruction_id"].get_str() + "/translate", tok));
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), avail);
    BOOST_CHECK_EQUAL(e->IntentCount(), intents);
}

BOOST_AUTO_TEST_SUITE_END()
