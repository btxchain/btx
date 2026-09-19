// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <set>
#include <string>
#include <vector>

namespace {

std::string EngineOut(const modelnet::HcpHttpResponse& r)
{
    return cr11_test::Json(r).write();
}

void HasToken(const std::string& haystack, const char* token)
{
    BOOST_CHECK_MESSAGE(haystack.find(token) != std::string::npos, std::string("missing token: ") + token);
}

#ifdef MODELNET_HCP_PORTAL_PATH
std::string ReadAll(const fs::path& p)
{
    std::ifstream in(fs::PathToString(p));
    BOOST_REQUIRE_MESSAGE(in.good(), fs::PathToString(p) + " missing");
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

fs::path CrfPortalDir()
{
    return fs::PathFromString(MODELNET_HCP_PORTAL_PATH).parent_path().parent_path() / "crf-portal";
}

std::string CrfHtml()
{
    return ReadAll(CrfPortalDir() / "index.html");
}

std::string CrfJs()
{
    return ReadAll(CrfPortalDir() / "portal.js");
}

std::string CrfSurface()
{
    return CrfHtml() + CrfJs();
}

std::string HcpHtml()
{
    return ReadAll(fs::PathFromString(MODELNET_HCP_PORTAL_PATH));
}
#endif

const std::string& PortalSurface()
{
#ifdef MODELNET_HCP_PORTAL_PATH
    static const std::string s = CrfSurface();
    return s;
#else
    BOOST_REQUIRE_MESSAGE(false, "MODELNET_HCP_PORTAL_PATH is not defined");
    static const std::string empty;
    return empty;
#endif
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_ux_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_ux_01_six_primary_screens)
{
    auto e = cr11_test::Lab();
    e->Cr11SetCognitiveHoldings(77);
    auto tok = cr11_test::Tok(*e);

    auto ext = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok));
    BOOST_REQUIRE_EQUAL(ext.status, 200);
    BOOST_REQUIRE_EQUAL(cr11_test::ObjType(ext), modelnet::HCP_TYPE_RESERVE_EXTENSION);
    const std::string ext_out = EngineOut(ext);
    HasToken(ext_out, "supported_features");
    HasToken(ext_out, "reserve");
    HasToken(ext_out, "committee");
    HasToken(ext_out, "programmes");
    HasToken(ext_out, "holdings");

    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };

    UniValue port(UniValue::VOBJ);
    port.pushKV("portfolio_id", "ux01-main");
    post("/reserve/portfolios", &port);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "ux01-policy");
    post("/reserve/policies", &pol);
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("position_id", "ux01-position");
    post("/capital/positions", &pos);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "ux01-program");
    post("/capital/programs", &prog);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "ux01-alloc");
    alloc.pushKV("maximum_exposure", "10");
    const std::string aid = post("/capital/allocations", &alloc)["body"]["allocation_id"].get_str();
    const std::string xid =
        post("/capital/allocations/" + aid + "/execute", nullptr)["body"]["execution_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "ux01-rule");
    post("/capital/approval-rules", &rule);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "ux01-approval");
    apr.pushKV("allocation_ref", aid);
    apr.pushKV("rule_ref", "ux01-rule");
    post("/capital/approvals", &apr);

    struct Screen {
        const char* html_token;
        std::string path;
        const char* object_type;
        const char* id_field;
        std::string id_value;
    };
    const std::vector<Screen> screens{
        {"data-page=\"overview\"", "/reserve/portfolios/ux01-main/snapshot", modelnet::HCP_TYPE_RESERVE_SNAPSHOT,
         "snapshot_id", ""},
        {"data-page=\"reserves\"", "/reserve/policies/ux01-policy", modelnet::HCP_TYPE_RESERVE_POLICY, "policy_id",
         "ux01-policy"},
        {"data-page=\"capabilities\"", "/capital/positions/ux01-position", modelnet::HCP_TYPE_CAPABILITY_POSITION,
         "position_id", "ux01-position"},
        {"data-page=\"build\"", "/capital/programs/ux01-program", modelnet::HCP_TYPE_RESEARCH_PROGRAM, "program_id",
         "ux01-program"},
        {"data-page=\"approvals\"", "/capital/approvals/ux01-approval", modelnet::HCP_TYPE_APPROVAL_REQUEST, "request_id",
         "ux01-approval"},
        {"data-page=\"activity\"", "/capital/executions/" + xid, modelnet::HCP_TYPE_CAPITAL_EXECUTION, "execution_id",
         xid},
    };
    const std::string html = PortalSurface();
    std::set<std::string> types;
    for (const auto& s : screens) {
        HasToken(html, s.html_token);
        auto r = e->Handle(hcp_test::AuthReq(*e, "GET", s.path, tok));
        BOOST_REQUIRE_MESSAGE(r.status == 200, s.path + " -> " + std::to_string(r.status));
        BOOST_CHECK_EQUAL(cr11_test::ObjType(r), s.object_type);
        HasToken(EngineOut(r), s.object_type);
        const UniValue b = cr11_test::Json(r)["body"];
        BOOST_REQUIRE_MESSAGE(b.exists(s.id_field), s.path + " missing " + s.id_field);
        HasToken(EngineOut(r), s.id_field);
        if (!s.id_value.empty()) {
            BOOST_CHECK_EQUAL(b[s.id_field].get_str(), s.id_value);
            HasToken(EngineOut(r), s.id_value.c_str());
        }
        types.insert(cr11_test::ObjType(r));
    }
    HasToken(html, ">Overview<");
    HasToken(html, ">Reserves<");
    HasToken(html, ">Capabilities<");
    HasToken(html, ">Build<");
    HasToken(html, ">Approvals<");
    HasToken(html, ">Activity<");
    BOOST_CHECK_EQUAL(types.size(), 6u);

    auto over = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/ux01-main/snapshot", tok));
    const std::string snap = EngineOut(over);
    HasToken(snap, "available_atoms");
    HasToken(snap, "committed_atoms");
    HasToken(snap, "cognitive_holdings_atoms");
    BOOST_CHECK_EQUAL(cr11_test::Json(over)["body"]["available_atoms"].get_str(), "990");
    BOOST_CHECK_EQUAL(cr11_test::Json(over)["body"]["committed_atoms"].get_str(), "10");
    BOOST_CHECK_EQUAL(cr11_test::Json(over)["body"]["cognitive_holdings_atoms"].get_str(), "77");
    BOOST_CHECK(cr11_test::Json(over)["body"]["nav_merged"].isFalse());

    BOOST_CHECK_EQUAL(post("/capital/reports", nullptr)["object_type"].get_str(), modelnet::HCP_TYPE_RESERVE_REPORT);
    BOOST_CHECK_EQUAL(types.count(modelnet::HCP_TYPE_RESERVE_REPORT), 0u);
    HasToken(html, "data-page=\"reports\"");

    for (const char* invented : {"/capital/dashboards", "/reserve/screens", "/capital/programs/ux01-program/screens"}) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "GET", invented, tok));
        BOOST_CHECK_EQUAL(r.status, 404);
        HasToken(EngineOut(r), "NOT_FOUND");
    }
}

BOOST_AUTO_TEST_CASE(cr11_ux_02_persistent_payer)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("label", "working");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &body));
    const std::string out = EngineOut(r);
    HasToken(out, "account_ref");
    HasToken(out, "account-demo");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["account_ref"].get_str(), "account-demo");
    const std::string html = PortalSurface();
    HasToken(html, "Legal payer");
    HasToken(html, "id=\"entity\"");
    HasToken(html, "id=\"portfolio\"");
    HasToken(html, "id=\"payer-banner\"");
}

BOOST_AUTO_TEST_CASE(cr11_ux_03_one_decision_packet)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "pkt-1");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 201);
    const std::string out = EngineOut(r);
    HasToken(out, "allocation_id");
    HasToken(out, "client_operation_id");
    HasToken(out, "pkt-1");
    HasToken(out, "maximum_exposure");
    HasToken(out, "legs");
    const std::string html = PortalSurface();
    HasToken(html, "One precise packet");
    HasToken(html, "id=\"packet\"");
    HasToken(html, "Maximum debit");
    HasToken(html, "Local effect");
}

BOOST_AUTO_TEST_CASE(cr11_ux_04_independent_local_permission)
{
    auto e = cr11_test::Lab();
    e->RevokeLocalGrant();
    std::string code, err;
    e->AcceptHandoff(hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code, err);
    HasToken(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
    const std::string html = PortalSurface();
    HasToken(html, "Independent device permission");
    HasToken(html, "Record local permission");
    HasToken(html, "Financial approval cannot override software trust");
}

BOOST_AUTO_TEST_CASE(cr11_ux_05_duplicate_click)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "click-1");
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string a1 = cr11_test::Json(r1)["body"]["allocation_id"].get_str();
    const std::string a2 = cr11_test::Json(r2)["body"]["allocation_id"].get_str();
    BOOST_CHECK_EQUAL(a1, a2);
    HasToken(EngineOut(r1), "client_operation_id");
    HasToken(EngineOut(r1), "click-1");
    HasToken(EngineOut(r2), a1.c_str());
    const std::string html = PortalSurface();
    HasToken(html, "Duplicate clicks reuse the same");
    HasToken(html, "client_operation_id");
}

BOOST_AUTO_TEST_CASE(cr11_ux_06_unknown_outcome_copy)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK(e->IntentState("nope").empty());
    e->ForceBroadcastUnknown("nope");
    const std::string state = e->IntentState("nope");
    HasToken(state, modelnet::HCP_ERR_BROADCAST_UNKNOWN);
    BOOST_CHECK_EQUAL(state, modelnet::HCP_ERR_BROADCAST_UNKNOWN);
    const std::string html = PortalSurface();
    HasToken(html, "Do not start a new payment");
    HasToken(html, "retry new payment");
    HasToken(html, "retry_new_payment");
    BOOST_CHECK(html.find(">Retry new payment<") == std::string::npos);
    BOOST_CHECK(html.find("id=\"retry-new-payment\"") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_ux_07_keyboard_and_reader)
{
    const std::string html = PortalSurface();
    HasToken(html, "Skip to capital workspace");
    HasToken(html, "focus-visible");
    HasToken(html, "min-height: 44px");
    HasToken(html, "aria-label=\"Primary\"");
    HasToken(html, "aria-current=\"page\"");
    HasToken(html, "role=\"status\"");
    HasToken(html, "aria-live");
    HasToken(html, "data-page=\"approvals\"");
#ifdef MODELNET_HCP_PORTAL_PATH
    const std::string hcp = HcpHtml();
    HasToken(hcp, "aria-label=\"Views\"");
    HasToken(hcp, "aria-current=\"page\"");
    HasToken(hcp, "data-view=\"approvals\"");
    HasToken(hcp, "<nav");
    HasToken(hcp, "Approvals");
#endif
}

BOOST_AUTO_TEST_CASE(cr11_ux_08_session_reauthentication)
{
    auto e = cr11_test::Lab();
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", "expired"));
    BOOST_CHECK_EQUAL(r.status, 401);
    HasToken(EngineOut(r), "TOKEN_INVALID");
    const std::string html = PortalSurface();
    HasToken(html, "Draft identifiers are retained");
    HasToken(html, "Re-authenticate");
    HasToken(html, "id=\"session-note\"");
}

BOOST_AUTO_TEST_CASE(cr11_ux_09_localized_units)
{
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(-5, 0, 10), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(100, 400, 250), 0);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(1000, 400, 250), 250);
    BOOST_CHECK_EQUAL(modelnet::Cr11Capacity(100, -8, 10), 10);
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("unit_mismatch", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 400);
    HasToken(EngineOut(r), "UNIT_MISMATCH");
    HasToken(EngineOut(r), "atoms vs cents vs tasks");
    const std::string html = PortalSurface();
    HasToken(html, "Display locale");
    HasToken(html, "日本語");
    HasToken(html, "Canonical atoms");
    HasToken(html, "overflow-wrap");
}

BOOST_AUTO_TEST_CASE(cr11_ux_10_free_public_journey)
{
    auto e = hcp_test::Lab(false);
    BOOST_CHECK(e->Cfg().walletless);
    BOOST_CHECK(!e->Cfg().finance_enabled);
    modelnet::HcpHttpRequest health;
    health.method = "GET";
    health.path = "/health";
    auto h = e->Handle(health);
    BOOST_CHECK_EQUAL(h.status, 200);
    const std::string out = EngineOut(h);
    HasToken(out, "walletless");
    HasToken(out, "automatic_spend_atoms");
    BOOST_CHECK(cr11_test::Json(h)["walletless"].isTrue());
    BOOST_CHECK(cr11_test::Json(h)["finance"].isFalse());
    BOOST_CHECK_EQUAL(cr11_test::Json(h)["automatic_spend_atoms"].getInt<int64_t>(), 0);
    const std::string html = PortalSurface();
    HasToken(html, "no CEX payment, new wallet, or subscription");
    HasToken(html, "Prepare locally");
    HasToken(html, "Public · free acquisition");
    HasToken(html, "automatic_spend_atoms");
}

BOOST_AUTO_TEST_SUITE_END()
