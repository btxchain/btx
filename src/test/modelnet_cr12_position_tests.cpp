// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_position_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_position_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("observation_id", "pos-replay");
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    a.pushKV("quantity", "1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a));
    BOOST_CHECK_EQUAL(r2.status, 201);
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_position_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    a.pushKV("quantity", "1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("source", "src-a");
    b.pushKV("generation", "1");
    b.pushKV("sequence", "0");
    b.pushKV("quantity", "9");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &b))),
                      modelnet::HCP_ERR_OBSERVATION_CONFLICT);
    auto br = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/breaks", tok));
    BOOST_CHECK(cr12_test::Body(br)["items"].size() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_position_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const std::string now = std::to_string(e->Now());
    const std::string later = std::to_string(e->Now() + 10000);
    UniValue cur(UniValue::VOBJ);
    cur.pushKV("observation_id", "pos-now");
    cur.pushKV("source", "src-a");
    cur.pushKV("generation", "1");
    cur.pushKV("sequence", "0");
    cur.pushKV("effective_at", now);
    cur.pushKV("recorded_at", now);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &cur)).status, 201);
    UniValue fut(UniValue::VOBJ);
    fut.pushKV("observation_id", "pos-future");
    fut.pushKV("source", "src-a");
    fut.pushKV("generation", "1");
    fut.pushKV("sequence", "1");
    fut.pushKV("effective_at", later);
    fut.pushKV("recorded_at", now);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &fut)).status, 201);
    auto req = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    req.query = "as_of=" + now + "&observed_cutoff=" + now;
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["items"].size(), 1);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["items"][0]["observation_id"].get_str(), "pos-now");
}

BOOST_AUTO_TEST_CASE(cr12_position_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const std::string t1 = std::to_string(e->Now());
    const std::string t2 = std::to_string(e->Now() + 5000);
    UniValue orig(UniValue::VOBJ);
    orig.pushKV("observation_id", "pos-orig");
    orig.pushKV("source", "src-a");
    orig.pushKV("generation", "1");
    orig.pushKV("sequence", "0");
    orig.pushKV("effective_at", t1);
    orig.pushKV("recorded_at", t1);
    orig.pushKV("quantity", "1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &orig)).status, 201);
    UniValue corr(UniValue::VOBJ);
    corr.pushKV("observation_id", "pos-corr");
    corr.pushKV("source", "src-a");
    corr.pushKV("generation", "1");
    corr.pushKV("sequence", "1");
    corr.pushKV("effective_at", t1);
    corr.pushKV("recorded_at", t2);
    corr.pushKV("quantity", "2");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &corr)).status, 201);
    auto early = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    early.query = "as_of=" + t1 + "&observed_cutoff=" + t1;
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(early))["items"].size(), 1);
    auto late = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    late.query = "as_of=" + t1 + "&observed_cutoff=" + t2;
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(late))["items"].size(), 2);
}

BOOST_AUTO_TEST_CASE(cr12_position_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("observation_id", "pos-closed");
    a.pushKV("status", "CLOSED");
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    const std::string now = std::to_string(e->Now());
    auto cur_req = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    cur_req.query = "as_of=" + now + "&observed_cutoff=" + now;
    auto cur = e->Handle(cur_req);
    BOOST_CHECK_EQUAL(cr12_test::Body(cur)["items"].size(), 0);
    auto hist = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    hist.query = "as_of=" + now + "&observed_cutoff=" + now + "&view=historical";
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hist))["items"].size(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_position_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("source", "src-a");
    b.pushKV("generation", "1");
    b.pushKV("sequence", "2");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &b)).status, 201);
    auto br = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/breaks", tok));
    BOOST_CHECK(cr12_test::Body(br)["items"].size() >= 1);
}

BOOST_AUTO_TEST_CASE(cr12_position_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue rows(UniValue::VARR);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("source", "src-a");
    ok.pushKV("sequence", "0");
    rows.push_back(ok);
    UniValue a(UniValue::VOBJ);
    a.pushKV("rows", rows);
    a.pushKV("one_invalid", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a));
    BOOST_CHECK_EQUAL(r.status, 400);
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 0);
}

BOOST_AUTO_TEST_CASE(cr12_position_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue cust(UniValue::VOBJ);
    cust.pushKV("observation_id", "pos-cust");
    cust.pushKV("source", "custody");
    cust.pushKV("generation", "1");
    cust.pushKV("sequence", "0");
    cust.pushKV("mandate", "MANAGED");
    cust.pushKV("beneficial_id", "lot-1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &cust)).status, 201);
    UniValue tre(UniValue::VOBJ);
    tre.pushKV("observation_id", "pos-tre");
    tre.pushKV("source", "treasury");
    tre.pushKV("generation", "1");
    tre.pushKV("sequence", "0");
    tre.pushKV("mandate", "NONE");
    tre.pushKV("beneficial_id", "lot-1");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &tre)).status, 201);
    const std::string now = std::to_string(e->Now());
    auto list = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    list.query = "as_of=" + now + "&observed_cutoff=" + now;
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(list))["items"].size(), 2);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    auto pr = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK_EQUAL(cr12_test::Body(pr)["metric_results"][0]["eligible_count"].getInt<int64_t>(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_position_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("observation_id", "pos-lot-a");
    a.pushKV("source", "src-a");
    a.pushKV("generation", "1");
    a.pushKV("sequence", "0");
    a.pushKV("address", "omnibus-1");
    a.pushKV("beneficial_id", "customer-a");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("observation_id", "pos-lot-b");
    b.pushKV("source", "src-a");
    b.pushKV("generation", "1");
    b.pushKV("sequence", "1");
    b.pushKV("address", "omnibus-1");
    b.pushKV("beneficial_id", "customer-b");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &b)).status, 201);
    const std::string now = std::to_string(e->Now());
    auto list = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    list.query = "as_of=" + now + "&observed_cutoff=" + now;
    auto items = cr12_test::Body(e->Handle(list))["items"];
    BOOST_CHECK_EQUAL(items.size(), 2);
    BOOST_CHECK(items[0]["beneficial_id"].get_str() != items[1]["beneficial_id"].get_str());
}

BOOST_AUTO_TEST_CASE(cr12_position_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("source", "src-a");
    a.pushKV("generation", "2");
    a.pushKV("sequence", "0");
    a.pushKV("new_generation", true);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &a)).status, 409);
    auto br = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/breaks", tok));
    BOOST_CHECK(cr12_test::Body(br)["items"].size() >= 1);
}

BOOST_AUTO_TEST_SUITE_END()
