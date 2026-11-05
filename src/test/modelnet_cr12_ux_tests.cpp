// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <test/util/sdk_process.h>
#include <util/fs.h>
#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <string>

#ifdef MODELNET_CRL12_PORTAL_PATH
namespace {
std::string Cr12PortalHtml()
{
    std::ifstream in(MODELNET_CRL12_PORTAL_PATH);
    BOOST_REQUIRE_MESSAGE(in.good(), "CRL12 portal HTML missing");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

fs::path Cr12SdkRoot()
{
    return fs::PathFromString(MODELNET_CRL12_PORTAL_PATH).parent_path().parent_path() / "crl12-sdk";
}

using sdk_test::Python3;
using sdk_test::Spawn;
using sdk_test::Which;

} // namespace
#endif

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_ux_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_ux_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("manifest_id", "ux-provider-a");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
    UniValue b(UniValue::VOBJ);
    b.pushKV("role", "DISCOVERY");
    b.pushKV("binding_id", "ux-bind-a");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &b)).status, 201);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("Connections") != std::string::npos);
    BOOST_CHECK(html.find("Discovery") != std::string::npos);
    BOOST_CHECK(html.find("Portfolio analytics") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("legal_entity_id", "le-other");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a))),
                      modelnet::HCP_ERR_ENTITY_SCOPE);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("legal_entity_id", "le-demo");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["legal_entity_id"].get_str(), "le-demo");
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("id=\"entity\"") != std::string::npos);
    BOOST_CHECK(html.find("Entity") != std::string::npos);
    BOOST_CHECK(html.find("Select an explicit legal payer") != std::string::npos);
    BOOST_CHECK(html.find("Family group") != std::string::npos);
    BOOST_CHECK(html.find("read only") != std::string::npos);
    BOOST_CHECK(html.find("selectedIndex===2") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue aum(UniValue::VOBJ);
    aum.pushKV("metric_kind", "AUM");
    auto ra = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/metrics", tok, &aum));
    BOOST_CHECK_EQUAL(cr12_test::Body(ra)["mandate_required"].isTrue(), true);
    BOOST_CHECK_EQUAL(cr12_test::Body(ra)["basis"].get_str(), "DIRECT_ONLY");
    UniValue auc(UniValue::VOBJ);
    auc.pushKV("metric_kind", "AUC");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/metrics", tok, &auc)).status, 201);
    BOOST_CHECK(cr12_test::Json(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/metrics", tok)))["items"].isArray());
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("AUM") != std::string::npos);
    BOOST_CHECK(html.find("AUC") != std::string::npos);
    BOOST_CHECK(html.find("As of") != std::string::npos);
    BOOST_CHECK(html.find("Not counted twice") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("source", "src");
    p.pushKV("generation", "1");
    p.pushKV("sequence", "1");
    p.pushKV("mandate", "MANAGED");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &p)).status, 201);
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("metric_kind", "AUM");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "PARTIAL");
    BOOST_CHECK(cr12_test::Body(r)["metric_results"][0]["value"].isNull());
    BOOST_CHECK(!cr12_test::Body(r)["metric_results"][0]["complete"].isTrue());
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("Partial view") != std::string::npos);
    BOOST_CHECK(html.find("Valuation unavailable") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/roles", tok)).status, 200);
    UniValue a(UniValue::VOBJ);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a)).status, 201);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("focus-visible") != std::string::npos);
    BOOST_CHECK(html.find("min-height:44px") != std::string::npos);
    BOOST_CHECK(html.find("label{min-height:44px") != std::string::npos);
    BOOST_CHECK(html.find("Skip to content") != std::string::npos);
    BOOST_CHECK(html.find("aria-current") != std::string::npos);
    BOOST_CHECK(html.find("aria-label=\"Primary\"") != std::string::npos);
    const std::string python = Python3();
    BOOST_REQUIRE_MESSAGE(!python.empty(), "python3 required");
    std::string out;
    const std::vector<std::string> cmd{python, fs::PathToString(Cr12SdkRoot() / "python/test_portal_a11y.py")};
    const int rc = Spawn(cmd, out);
    BOOST_REQUIRE_MESSAGE(rc == 0, "portal a11y unittest rc=" + std::to_string(rc) + "\n" + out);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pr(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr));
    BOOST_CHECK_EQUAL(r.status, 201);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("aria-live") != std::string::npos);
    BOOST_CHECK(html.find("aria-atomic") != std::string::npos);
    BOOST_CHECK(html.find("role=\"status\"") != std::string::npos);
    BOOST_CHECK(html.find("id=\"notice\"") != std::string::npos);
    BOOST_CHECK(html.find("CR12_SEC_SENTINEL") == std::string::npos);
    BOOST_CHECK(html.find("fetch(") == std::string::npos);
    BOOST_CHECK(html.find("XMLHttpRequest") == std::string::npos);
    BOOST_CHECK(html.find("http://") == std::string::npos);
    BOOST_CHECK(html.find("https://") == std::string::npos);
    BOOST_CHECK(html.find("executeAllocation") == std::string::npos);
    BOOST_CHECK(html.find("/rpc") == std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue s(UniValue::VOBJ);
    s.pushKV("kind", "RESERVE_PRICE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &s));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["financial_units"].get_str(), "atoms");
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["operational_units"].get_str(), "readiness");
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("Money and capability have separate timelines") != std::string::npos);
    BOOST_CHECK(html.find("data-tab=\"activity\"") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("redaction", "PRIVATE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &ex));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["redaction"].get_str(), "PRIVATE");
    BOOST_CHECK(!cr12_test::Body(r)["privacy_policy_ref"].get_str().empty());
    auto analytics = cr12_test::Tok(*e, cr12_test::AnalyticsScopes());
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", analytics))),
                      modelnet::HCP_ERR_SCOPE);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("export") != std::string::npos || html.find("Export") != std::string::npos);
    BOOST_CHECK(html.find("signed manifest") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("desktop_context", true);
    a.pushKV("requested_action", "DRAFT_CAPABILITY_ACQUISITION");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    BOOST_CHECK(cr12_test::Body(r)["execute"].isFalse());
    std::string code;
    const UniValue plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty() || code == "ORIGIN_DENIED");
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("draft") != std::string::npos || html.find("Draft") != std::string::npos);
    BOOST_CHECK(html.find("no network, signing, funding or local runtime execution") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_CASE(cr12_ux_10)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &a));
    const std::string id = cr12_test::Body(r)["binding_id"].get_str();
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/" + id + "/revoke", tok)).status, 200);
    BOOST_CHECK(e->DevicePaired("device-demo"));
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("objective", "own-then-run");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan)).status, 201);
#ifdef MODELNET_CRL12_PORTAL_PATH
    const std::string html = Cr12PortalHtml();
    BOOST_CHECK(html.find("original recovery") != std::string::npos || html.find("Funds and original recovery") != std::string::npos);
#endif
}

BOOST_AUTO_TEST_SUITE_END()
