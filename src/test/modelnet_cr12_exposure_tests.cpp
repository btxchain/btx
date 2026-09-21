// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_exposure_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_exposure_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    UniValue edge(UniValue::VOBJ);
    edge.pushKV("parent", "fund");
    edge.pushKV("child", "holding");
    edge.pushKV("kind", "FINANCIAL");
    edge.pushKV("weight", "1");
    links.push_back(edge);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("links", links);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &ok)).status, 201);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("links", links);
    bad.pushKV("add_parent_and_children", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &bad))),
                      modelnet::HCP_ERR_LOOKTHROUGH);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    UniValue ab(UniValue::VOBJ);
    ab.pushKV("parent", "A");
    ab.pushKV("child", "B");
    ab.pushKV("kind", "FINANCIAL");
    ab.pushKV("weight", "0.5");
    links.push_back(ab);
    UniValue ba(UniValue::VOBJ);
    ba.pushKV("parent", "B");
    ba.pushKV("child", "A");
    ba.pushKV("kind", "FINANCIAL");
    ba.pushKV("weight", "0.5");
    links.push_back(ba);
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body))),
                      modelnet::HCP_ERR_GRAPH_CYCLE);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    for (int i = 0; i <= modelnet::HCP_CR12_MAX_LOOKTHROUGH_DEPTH; ++i) {
        UniValue edge(UniValue::VOBJ);
        edge.pushKV("parent", "n" + std::to_string(i));
        edge.pushKV("child", "n" + std::to_string(i + 1));
        edge.pushKV("kind", "OPERATIONAL");
        links.push_back(edge);
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body))),
                      modelnet::HCP_ERR_GRAPH_DEPTH);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    UniValue a(UniValue::VOBJ);
    a.pushKV("parent", "p");
    a.pushKV("child", "c1");
    a.pushKV("kind", "FINANCIAL");
    a.pushKV("weight", "0.6");
    links.push_back(a);
    UniValue b(UniValue::VOBJ);
    b.pushKV("parent", "p");
    b.pushKV("child", "c2");
    b.pushKV("kind", "FINANCIAL");
    b.pushKV("weight", "0.6");
    links.push_back(b);
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body))),
                      modelnet::HCP_ERR_WEIGHT_OVERFLOW);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("coverage_bps", 8000);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["coverage_bps"].getInt<int64_t>(), 8000);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["unresolved_residual_bps"].getInt<int64_t>(), 2000);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue edge(UniValue::VOBJ);
    edge.pushKV("parent", "capability");
    edge.pushKV("child", "runtime");
    edge.pushKV("kind", "OPERATIONAL");
    edge.pushKV("weight", "999");
    UniValue links(UniValue::VARR);
    links.push_back(edge);
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), e->AccountAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_exposure_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue nanw(UniValue::VOBJ);
    nanw.pushKV("kind", "FINANCIAL");
    nanw.pushKV("weight", "NaN");
    nanw.pushKV("parent", "p");
    nanw.pushKV("child", "c");
    UniValue links(UniValue::VARR);
    links.push_back(nanw);
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body))),
                      modelnet::HCP_ERR_NONFINITE);
    UniValue neg(UniValue::VOBJ);
    neg.pushKV("kind", "FINANCIAL");
    neg.pushKV("weight", "-0.1");
    neg.pushKV("parent", "p");
    neg.pushKV("child", "c");
    UniValue links2(UniValue::VARR);
    links2.push_back(neg);
    UniValue body2(UniValue::VOBJ);
    body2.pushKV("links", links2);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body2))),
                      modelnet::HCP_ERR_NONFINITE);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue edge(UniValue::VOBJ);
    edge.pushKV("parent", "p");
    edge.pushKV("child", "c");
    edge.pushKV("kind", "FINANCIAL");
    edge.pushKV("weight", "1");
    UniValue links(UniValue::VARR);
    links.push_back(edge);
    UniValue a(UniValue::VOBJ);
    a.pushKV("link_id", "exp-dup");
    a.pushKV("links", links);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &a)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &a)).status, 201);
    auto listed = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/exposures", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(listed)["items"].size(), 1);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue links(UniValue::VARR);
    for (int i = 0; i <= modelnet::HCP_CR12_MAX_GRAPH_EDGES; ++i) {
        UniValue edge(UniValue::VOBJ);
        edge.pushKV("parent", "root");
        edge.pushKV("child", std::to_string(i));
        edge.pushKV("kind", "OPERATIONAL");
        links.push_back(edge);
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("links", links);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &body))),
                      modelnet::HCP_ERR_GRAPH_LIMIT);
}

BOOST_AUTO_TEST_CASE(cr12_exposure_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t avail = e->Crl12NativeAvailable("account-demo");
    UniValue asset(UniValue::VOBJ);
    asset.pushKV("kind", "CAPABILITY");
    auto ar = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &asset));
    UniValue rights(UniValue::VOBJ);
    rights.pushKV("issuer", "unaccepted-issuer");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + cr12_test::Body(ar)["asset_id"].get_str() + "/rights", tok, &rights));
    UniValue scn(UniValue::VOBJ);
    scn.pushKV("kind", "RIGHTS_LOSS");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &scn));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["distinct_methodology"].isTrue());
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), avail);
}

BOOST_AUTO_TEST_SUITE_END()
