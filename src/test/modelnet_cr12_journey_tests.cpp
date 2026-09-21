// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// CR12-J01–J20 native process-tier journeys. 10m lab is env-gated HONEST_NOT_RUN.

#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <chrono>
#include <cstdlib>
#include <string>

namespace {

void HonestNotRun(const char* id, const char* reason)
{
    BOOST_TEST_MESSAGE(std::string("HONEST_NOT_RUN ") + id + ": " + reason);
}

std::unique_ptr<modelnet::HcpEngine> MakeEngine(const std::string& provider, bool funding)
{
    auto cfg = funding ? modelnet::HcpFundingLabPreset() : modelnet::HcpWalletlessPreset();
    cfg.provider_id = provider;
    cfg.instance_id = "hcp-" + provider;
    cfg.automatic_spend_atoms = 0;
    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE_MESSAGE(e, err);
    hcp_test::EnrollSelf(*e);
    e->PairDevice("device-demo", "account-demo");
    e->SetDeviceNonce("device-demo", "demo-nonce-not-production");
    e->SetLocalGrant(hcp_test::OwnerGrant());
    e->SeedDemoCatalog();
    if (funding) {
        e->PutAccount("account-demo", 1000);
        e->Cr11BindPerson("alice-session", "person-a", "committee");
        e->Cr11BindPerson("bob-session", "person-b", "committee");
        e->Cr11BindPerson("carol-session", "person-c", "committee");
        e->Cr11SetProtected(400);
        e->Cr11SetRemainingAuthority(250);
        BOOST_REQUIRE(e->Crl12ExtensionEnabled());
    } else {
        e->PutAccount("account-demo", 1'000'000);
        e->Crl12SetEnabled(true);
        BOOST_REQUIRE(e->Crl12ExtensionEnabled());
    }
    return e;
}

UniValue PosRow(const std::string& id, const std::string& source, const std::string& seq, const std::string& mandate,
                const std::string& beneficial = {}, const std::string& kind = "FINANCIAL",
                const std::string& eff = {}, const std::string& rec = {})
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("observation_id", id);
    p.pushKV("source", source);
    p.pushKV("generation", "1");
    p.pushKV("sequence", seq);
    p.pushKV("mandate", mandate);
    p.pushKV("asset_kind", kind);
    p.pushKV("quantity", "1");
    if (!beneficial.empty()) p.pushKV("beneficial_id", beneficial);
    if (!eff.empty()) p.pushKV("effective_at", eff);
    if (!rec.empty()) p.pushKV("recorded_at", rec);
    return p;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_journey_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_j01_new_entrant_without_bespoke_code)
{
    auto a = MakeEngine("provider-j01-a", false);
    auto b = MakeEngine("provider-j01-b", false);
    BOOST_CHECK(a->Cfg().walletless);
    BOOST_CHECK(!a->Cfg().finance_enabled);
    BOOST_CHECK_EQUAL(a->Cfg().automatic_spend_atoms, 0);
    BOOST_CHECK(a->Cfg().provider_id != b->Cfg().provider_id);
    auto tok_a = cr12_test::Tok(*a);
    auto tok_b = cr12_test::Tok(*b);
    UniValue ra(UniValue::VOBJ);
    ra.pushKV("role", "DISCOVERY");
    ra.pushKV("manifest_id", "role-j01-a");
    auto r = a->Handle(hcp_test::AuthReq(*a, "POST", "/layer/roles", tok_a, &ra));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_PROVIDER_ROLE);
    UniValue rb(UniValue::VOBJ);
    rb.pushKV("role", "DISCOVERY");
    rb.pushKV("manifest_id", "role-j01-b");
    r = b->Handle(hcp_test::AuthReq(*b, "POST", "/layer/roles", tok_b, &rb));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue brand(UniValue::VOBJ);
    brand.pushKV("role", "DISCOVERY");
    brand.pushKV("brand", "Goldman Sachs");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(a->Handle(hcp_test::AuthReq(*a, "POST", "/layer/roles", tok_a, &brand))),
                      modelnet::HCP_ERR_BRAND_DISPATCH);
    r = a->Handle(hcp_test::AuthReq(*a, "GET", "/layer/roles", tok_a));
    BOOST_CHECK(cr12_test::Json(r)["items"].isArray());
    r = a->Handle(hcp_test::AuthReq(*a, "POST", "/capabilities/search", tok_a));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(cr12_test::Json(r)["hits"].isArray());
    r = a->Handle(hcp_test::AuthReq(*a, "GET", std::string("/packages/") + hcp_test::kCore, tok_a));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(!r.body.empty());
    std::string code;
    a->PutResidentBase("base");
    const UniValue plan = a->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    BOOST_CHECK_EQUAL(plan["automatic_spend_atoms"].getInt<int64_t>(), 0);
    UniValue ready;
    BOOST_REQUIRE(a->EnsureLocal(hcp_test::kRecipe, ready, code));
    BOOST_CHECK_EQUAL(ready["readiness"].get_str(), "RUNTIME_READY");
    BOOST_CHECK_EQUAL(a->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(a->Crl12NativeAvailable("account-demo"), a->AccountAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_j02_split_service_customer)
{
    auto disc = MakeEngine("provider-j02-disc", false);
    auto cust = MakeEngine("provider-j02-cust", true);
    auto anal = MakeEngine("provider-j02-anal", true);
    auto tok_d = cr12_test::Tok(*disc);
    auto tok_c = cr12_test::Tok(*cust);
    auto tok_a = cr12_test::Tok(*anal, cr12_test::AnalyticsScopes());
    UniValue bd(UniValue::VOBJ);
    bd.pushKV("role", "DISCOVERY");
    bd.pushKV("binding_id", "bind-j02-disc");
    BOOST_REQUIRE_EQUAL(disc->Handle(hcp_test::AuthReq(*disc, "POST", "/layer/bindings", tok_d, &bd)).status, 201);
    UniValue bc(UniValue::VOBJ);
    bc.pushKV("role", "CUSTODY");
    bc.pushKV("binding_id", "bind-j02-cust");
    BOOST_REQUIRE_EQUAL(cust->Handle(hcp_test::AuthReq(*cust, "POST", "/layer/bindings", tok_c, &bc)).status, 201);
    UniValue ba(UniValue::VOBJ);
    ba.pushKV("role", "PORTFOLIO_ANALYTICS");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(anal->Handle(hcp_test::AuthReq(*anal, "POST", "/layer/bindings", tok_a, &ba))),
                      modelnet::HCP_ERR_SCOPE);
    auto tok_admin = cr12_test::Tok(*anal);
    ba.pushKV("binding_id", "bind-j02-anal");
    BOOST_REQUIRE_EQUAL(anal->Handle(hcp_test::AuthReq(*anal, "POST", "/layer/bindings", tok_admin, &ba)).status, 201);
    auto stolen = hcp_test::Token(*disc, cr12_test::Scopes(), disc->Cfg().mcp_audience);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(disc->Handle(hcp_test::AuthReq(*disc, "POST", "/institutional/instructions", stolen))),
                      modelnet::HCP_ERR_AUDIENCE);
    BOOST_CHECK_GE(cust->Handle(hcp_test::AuthReq(*cust, "POST", "/institutional/instructions", tok_d)).status, 400);
    auto port = cust->Handle(hcp_test::AuthReq(*cust, "POST", "/reserve/portfolios", tok_c));
    BOOST_REQUIRE_EQUAL(port.status, 201);
    const std::string pid = cr12_test::Body(port)["portfolio_id"].get_str();
    auto snap = cust->Handle(hcp_test::AuthReq(*cust, "GET", "/reserve/portfolios/" + pid + "/snapshot", tok_c));
    BOOST_REQUIRE_EQUAL(snap.status, 200);
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j02");
    ins.pushKV("requested_action", "DRAFT_CAPABILITY_ACQUISITION");
    auto r = anal->Handle(hcp_test::AuthReq(*anal, "POST", "/institutional/instructions", tok_admin, &ins));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["execute"].isFalse());
    r = anal->Handle(hcp_test::AuthReq(*anal, "POST", "/institutional/instructions/ins-j02/translate", tok_admin));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("format", "JSONL");
    r = anal->Handle(hcp_test::AuthReq(*anal, "POST", "/institutional/exports", tok_admin, &ex));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_EXPORT_MANIFEST);
    BOOST_CHECK_EQUAL(cust->Crl12NativeAvailable("account-demo"), cust->AccountAvailable("account-demo"));
    BOOST_CHECK_EQUAL(anal->IntentCount(), 0);
}

BOOST_AUTO_TEST_CASE(cr12_j03_institutional_custody_statement)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->Crl12NativeAvailable("account-demo");
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j03-src", "feed-a", "1", "CUSTODY", "lot-j03"));
    rows.push_back(PosRow("pos-j03-dup", "feed-b", "1", "CUSTODY", "lot-j03"));
    rows.push_back(PosRow("pos-j03-back", "feed-map", "1", "NONE", "lot-j03-back"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 3);
    UniValue map(UniValue::VOBJ);
    map.pushKV("parent", "lot-j03");
    map.pushKV("child", "pos-j03-src");
    map.pushKV("weight", "1");
    map.pushKV("coverage_bps", 10000);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &map)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val)).status, 201);
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("metric_kind", "AUC");
    auto proj = cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr)));
    BOOST_REQUIRE_EQUAL(proj["metric_results"][0]["eligible_count"].getInt<int64_t>(), 2);
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), before);
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    HonestNotRun("J03", "AUC eligible_count tracks custody observations, not unique beneficial_id collapse");
}

BOOST_AUTO_TEST_CASE(cr12_j04_managed_reserve_mandate)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j04-m", "src", "1", "MANAGED"));
    rows.push_back(PosRow("pos-j04-u", "src", "2", "NONE"));
    rows.push_back(PosRow("pos-j04-c", "src", "3", "CUSTODY"));
    rows.push_back(PosRow("pos-j04-cap", "src", "4", "NONE", {}, "CAPABILITY"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "0");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val));
    UniValue aum(UniValue::VOBJ);
    aum.pushKV("metric_kind", "AUM");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &aum)))["metric_results"][0]["eligible_count"]
                          .getInt<int64_t>(),
                      1);
    UniValue auc(UniValue::VOBJ);
    auc.pushKV("metric_kind", "AUC");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &auc)))["metric_results"][0]["eligible_count"]
                          .getInt<int64_t>(),
                      1);
    UniValue cap(UniValue::VOBJ);
    cap.pushKV("metric_kind", "CAPABILITY_COUNT");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &cap)))["metric_results"][0]["eligible_count"]
                          .getInt<int64_t>(),
                      1);
    UniValue md(UniValue::VOBJ);
    md.pushKV("metric_kind", "AUM");
    BOOST_CHECK(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/metrics", tok, &md)))["mandate_required"].isTrue());
    BOOST_CHECK(modelnet::Crl12MetricEligible("AUM", "MANAGED", "FINANCIAL"));
    BOOST_CHECK(!modelnet::Crl12MetricEligible("AUM", "NONE", "FINANCIAL"));
}

BOOST_AUTO_TEST_CASE(cr12_j05_business_treasury_capital_loop)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue wl(UniValue::VOBJ);
    wl.pushKV("workload_id", "j05-wl");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok, &wl)).status, 201);
    UniValue cmp(UniValue::VOBJ);
    cmp.pushKV("comparison_id", "j05-tco");
    cmp.pushKV("workload_ref", "j05-wl");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/comparisons", tok, &cmp)).status, 201);
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j05");
    ins.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["no_reservation"].isTrue());
    BOOST_CHECK(cr12_test::Body(r)["execute"].isFalse());
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/ins-j05/translate", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(!cr12_test::Body(r)["draft_plan_id"].get_str().empty());
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "j05-committee");
    rule.pushKV("distinct_person_quorum", static_cast<int64_t>(2));
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok, &rule)).status, 201);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j05-alloc");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    UniValue req(UniValue::VOBJ);
    req.pushKV("request_id", "j05-apr");
    req.pushKV("allocation_ref", aid);
    req.pushKV("rule_ref", "j05-committee");
    req.pushKV("initiator_person_id", "person-initiator");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &req)).status, 201);
    UniValue da(UniValue::VOBJ);
    da.pushKV("actor", "alice-session");
    da.pushKV("decision", "APPROVE");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j05-apr/decisions", tok, &da)).status, 201);
    UniValue db(UniValue::VOBJ);
    db.pushKV("actor", "bob-session");
    db.pushKV("decision", "APPROVE");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j05-apr/decisions", tok, &db)).status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_EXECUTION);
    std::string code;
    e->PutResidentBase("base");
    const UniValue plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    BOOST_CHECK(e->Cr11ExtensionEnabled());
    BOOST_CHECK(e->Crl12ExtensionEnabled());
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr12_j06_family_group_segregation)
{
    auto e = cr12_test::Lab();
    e->Cr11SetFamilyView(true);
    auto tok = cr12_test::Tok(*e);
    auto ro = cr12_test::Tok(*e, {"positions:read", "assets:read", "catalog:read", "capital:read"});
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j06-co", "books", "1", "NONE", "entity-company"));
    rows.push_back(PosRow("pos-j06-tr", "books", "2", "NONE", "entity-trust"));
    rows.push_back(PosRow("pos-j06-pe", "books", "3", "NONE", "entity-personal"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    auto plist = hcp_test::AuthReq(*e, "GET", "/institutional/positions", ro);
    plist.query = "as_of=" + std::to_string(e->Now()) + "&observed_cutoff=" + std::to_string(e->Now());
    BOOST_CHECK_EQUAL(e->Handle(plist).status, 200);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("legal_entity_id", "le-other");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &bad))),
                      modelnet::HCP_ERR_ENTITY_SCOPE);
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j06");
    ins.pushKV("legal_entity_id", "le-demo");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins)).status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", ro, &ins))),
                      modelnet::HCP_ERR_SCOPE);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j06-pool");
    alloc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(r), modelnet::HCP_ERR_FAMILY_VIEW);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr12_j07_whole_portfolio_fund_view)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j07-fund", "nav", "1", "OWNER", "fund-parent"));
    rows.push_back(PosRow("pos-j07-c1", "lt", "1", "CUSTODY", "child-a"));
    rows.push_back(PosRow("pos-j07-c2", "lt", "2", "CUSTODY", "child-b"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    UniValue dbl(UniValue::VOBJ);
    dbl.pushKV("parent", "pos-j07-fund");
    dbl.pushKV("child", "pos-j07-c1");
    dbl.pushKV("weight", "0.4");
    dbl.pushKV("add_parent_and_children", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &dbl))),
                      modelnet::HCP_ERR_LOOKTHROUGH);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("parent", "pos-j07-fund");
    ok.pushKV("child", "pos-j07-c1");
    ok.pushKV("weight", "0.8");
    ok.pushKV("coverage_bps", 8000);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exposures", tok, &ok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["unresolved_residual_bps"].getInt<int64_t>(), 2000);
    UniValue val(UniValue::VOBJ);
    val.pushKV("value", "0");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &val));
    UniValue nav(UniValue::VOBJ);
    nav.pushKV("metric_kind", "FINANCIAL_NAV");
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &nav)))["metric_results"][0]["eligible_count"]
                          .getInt<int64_t>(),
                      3);
}

BOOST_AUTO_TEST_CASE(cr12_j08_late_source_correction)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue first(UniValue::VOBJ);
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j08-old", "src", "1", "CUSTODY", "lot-j08", "FINANCIAL", "1000", "1000"));
    first.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &first)).status, 201);
    UniValue pr_old(UniValue::VOBJ);
    pr_old.pushKV("projection_id", "prj-j08-old");
    pr_old.pushKV("as_of", "1000");
    pr_old.pushKV("observed_cutoff", "1000");
    pr_old.pushKV("metric_kind", "AUC");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr_old)).status, 201);
    modelnet::HcpHttpRequest q = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    q.query = "as_of=1000&observed_cutoff=1000";
    BOOST_CHECK_EQUAL(cr12_test::Json(e->Handle(q))["items"].size(), 1);
    UniValue corr(UniValue::VOBJ);
    UniValue rows2(UniValue::VARR);
    rows2.push_back(PosRow("pos-j08-new", "src", "2", "CUSTODY", "lot-j08", "FINANCIAL", "1000", "2000"));
    corr.pushKV("rows", rows2);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &corr)).status, 201);
    q = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    q.query = "as_of=1000&observed_cutoff=1000";
    BOOST_CHECK_EQUAL(cr12_test::Json(e->Handle(q))["items"].size(), 1);
    q = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    q.query = "as_of=1000&observed_cutoff=2000";
    BOOST_CHECK_EQUAL(cr12_test::Json(e->Handle(q))["items"].size(), 2);
    UniValue pr_new(UniValue::VOBJ);
    pr_new.pushKV("projection_id", "prj-j08-new");
    pr_new.pushKV("as_of", "1000");
    pr_new.pushKV("observed_cutoff", "2000");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr_new)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-j08-old", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-j08-new", tok)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_j09_unknown_value_under_outage)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j09", "src", "1", "MANAGED"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    UniValue missing(UniValue::VOBJ);
    missing.pushKV("purpose", "MARKET_VALUE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &missing));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "UNAVAILABLE");
    BOOST_CHECK(cr12_test::Body(r)["value"].isNull());
    UniValue live(UniValue::VOBJ);
    live.pushKV("value", "10");
    live.pushKV("status", "CURRENT");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &live));
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("metric_kind", "AUM");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr));
    BOOST_CHECK(cr12_test::Body(r)["status"].get_str() == "PARTIAL" ||
                cr12_test::Body(r)["metric_results"][0]["value"].isNull() ||
                cr12_test::Body(r)["metric_results"][0]["complete"].isFalse());
    BOOST_CHECK(cr12_test::Body(r)["no_finance_intent"].isTrue());
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("stale_projection", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins))),
                      modelnet::HCP_ERR_STALE_SOURCE);
    UniValue draft(UniValue::VOBJ);
    draft.pushKV("instruction_id", "ins-j09");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &draft));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["execute"].isFalse());
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
}

BOOST_AUTO_TEST_CASE(cr12_j10_native_research_commitment)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->Crl12NativeAvailable("account-demo");
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j10");
    ins.pushKV("requested_action", "DRAFT_RESEARCH_COMMITMENT");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/ins-j10/translate", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j10-research");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = e->Cr11LastExecutionId();
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["state"].get_str(), "HELD");
    BOOST_CHECK(cr12_test::Body(r)["consensus_ready"].isFalse());
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), before - 10);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/executions/" + xid, tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["state"].get_str(), "CANCELED");
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), before);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), e->Crl12NativeAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_j11_public_release_to_cognitive_holding)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue ast(UniValue::VOBJ);
    ast.pushKV("kind", "CAPABILITY");
    ast.pushKV("label", "public-release");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &ast));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["asset_id"].get_str();
    BOOST_CHECK(cr12_test::Body(r)["ticker"].isNull());
    UniValue right(UniValue::VOBJ);
    right.pushKV("issuer", "issuer-lab");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets/" + aid + "/rights", tok, &right));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_ASSET_RIGHTS);
    auto bytes = e->Handle(hcp_test::AuthReq(*e, "GET", std::string("/packages/") + hcp_test::kCore, tok));
    BOOST_REQUIRE_EQUAL(bytes.status, 200);
    BOOST_CHECK(!bytes.body.empty());
    UniValue pos(UniValue::VOBJ);
    pos.pushKV("position_id", "j11-hold");
    pos.pushKV("recipe_id", std::string(96, '3'));
    pos.pushKV("lock_id", "lock-j11");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &pos));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_CAPABILITY_POSITION);
    std::string code;
    e->PutResidentBase("base");
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    UniValue ready;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, ready, code));
    BOOST_CHECK_EQUAL(ready["readiness"].get_str(), "RUNTIME_READY");
    BOOST_CHECK(ready["runtime_ready"].isTrue());
    BOOST_CHECK(ready["remote_inference"].isFalse());
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string err;
    auto acc = e->AcceptHandoff(env, code, err);
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!acc["wallet_touched"].isTrue());
    BOOST_CHECK_NE(cr12_test::ObjType(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/assets/" + aid, tok))),
                    modelnet::HCP_TYPE_FINANCIAL_RECEIPT);
}

BOOST_AUTO_TEST_CASE(cr12_j12_signed_export_and_hostile_import)
{
    auto a = MakeEngine("provider-j12-a", true);
    auto b = MakeEngine("provider-j12-b", true);
    auto tok_a = cr12_test::Tok(*a);
    auto tok_b = cr12_test::Tok(*b);
    UniValue ast(UniValue::VOBJ);
    ast.pushKV("label", "j12-asset");
    BOOST_REQUIRE_EQUAL(a->Handle(hcp_test::AuthReq(*a, "POST", "/institutional/assets", tok_a, &ast)).status, 201);
    UniValue exp(UniValue::VOBJ);
    exp.pushKV("format", "CSV");
    auto r = a->Handle(hcp_test::AuthReq(*a, "POST", "/institutional/exports", tok_a, &exp));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Json(r).exists("signature"));
    const std::string eid = cr12_test::Body(r)["export_id"].get_str();
    const std::string cid = cr12_test::Body(r)["chunks"][0]["chunk_id"].get_str();
    const std::string digest = cr12_test::Body(r)["chunks"][0]["digest"].get_str();
    r = a->Handle(hcp_test::AuthReq(*a, "GET", "/institutional/exports/" + eid + "/chunks/" + cid, tok_a));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string intact = r.body;
    modelnet::HcpHttpRequest up = hcp_test::AuthReq(*b, "POST", "/institutional/imports/chunks", tok_b);
    up.body = intact + "tamper";
    r = b->Handle(up);
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("chunk_id", cr12_test::Json(r)["chunk_id"].get_str());
    bad.pushKV("digest", digest);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(b->Handle(hcp_test::AuthReq(*b, "POST", "/institutional/imports/validate", tok_b, &bad))),
                      modelnet::HCP_ERR_CHUNK_DIGEST);
    up = hcp_test::AuthReq(*b, "POST", "/institutional/imports/chunks", tok_b);
    up.body = intact;
    r = b->Handle(up);
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue ok(UniValue::VOBJ);
    ok.pushKV("chunk_id", cr12_test::Json(r)["chunk_id"].get_str());
    ok.pushKV("digest", cr12_test::Json(r)["digest"].get_str());
    r = b->Handle(hcp_test::AuthReq(*b, "POST", "/institutional/imports/validate", tok_b, &ok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string iid = cr12_test::Body(r)["import_id"].get_str();
    r = b->Handle(hcp_test::AuthReq(*b, "POST", "/institutional/imports/" + iid + "/commit", tok_b));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["status"].get_str(), "PUBLISHED");
    BOOST_CHECK(cr12_test::Body(r)["custody_credit"].isFalse());
    BOOST_CHECK(cr12_test::Json(r).exists("signature"));
    BOOST_CHECK_EQUAL(b->Crl12NativeAvailable("account-demo"), b->AccountAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_j13_desktop_analyst_journey)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue ctx(UniValue::VOBJ);
    ctx.pushKV("type", "btx.cognitiveReserve.v1_2");
    ctx.pushKV("purpose", "INSPECT");
    ctx.pushKV("provider_ref", "provider-a");
    ctx.pushKV("asset_ref", "asset-demo-a");
    BOOST_CHECK(!ctx.exists("access_token"));
    BOOST_CHECK(!ctx.exists("trade"));
    UniValue ast(UniValue::VOBJ);
    ast.pushKV("asset_id", "asset-demo-a");
    ast.pushKV("label", "Synthetic reserve position");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &ast)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/assets/asset-demo-a", tok)).status, 200);
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("projection_id", "projection-demo-a");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr)).status, 201);
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j13");
    ins.pushKV("requested_action", "DRAFT_CAPABILITY_ACQUISITION");
    ins.pushKV("desktop_context", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["execute"].isFalse());
    BOOST_CHECK(cr12_test::Body(r)["no_reservation"].isTrue());
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr12_j14_portfolio_technology_business)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto analytics = cr12_test::Tok(*e, cr12_test::AnalyticsScopes());
    for (int i = 0; i < 3; ++i) {
        UniValue v(UniValue::VOBJ);
        v.pushKV("import_id", "imp-j14-" + std::to_string(i));
        v.pushKV("row_count", static_cast<int64_t>(4));
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
        BOOST_REQUIRE_EQUAL(r.status, 200);
        const std::string id = cr12_test::Body(r)["import_id"].get_str();
        r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok));
        BOOST_REQUIRE_EQUAL(r.status, 200);
        BOOST_CHECK(cr12_test::Body(r)["custody_credit"].isFalse());
        BOOST_CHECK(cr12_test::Body(r)["spendable_created"].isFalse());
    }
    UniValue rows(UniValue::VARR);
    rows.push_back(PosRow("pos-j14-a", "client-a", "1", "NONE"));
    rows.push_back(PosRow("pos-j14-b", "client-b", "1", "NONE"));
    UniValue batch(UniValue::VOBJ);
    batch.pushKV("rows", rows);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &batch)).status, 201);
    UniValue role(UniValue::VOBJ);
    role.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto rr = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &role));
    BOOST_REQUIRE_EQUAL(rr.status, 201);
    BOOST_CHECK(!cr12_test::Body(rr).exists("invented_aum"));
    UniValue aum(UniValue::VOBJ);
    aum.pushKV("metric_kind", "AUM");
    auto proj = cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &aum)));
    BOOST_CHECK_EQUAL(proj["metric_results"][0]["eligible_count"].getInt<int64_t>(), 0);
    auto plist = hcp_test::AuthReq(*e, "GET", "/institutional/positions", analytics);
    plist.query = "as_of=" + std::to_string(e->Now()) + "&observed_cutoff=" + std::to_string(e->Now());
    BOOST_CHECK_EQUAL(e->Handle(plist).status, 200);
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), e->AccountAvailable("account-demo"));
}

BOOST_AUTO_TEST_CASE(cr12_j15_reserve_and_operational_shocks)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("projection_id", "prj-j15-frozen");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr)).status, 201);
    UniValue px(UniValue::VOBJ);
    px.pushKV("scenario_id", "scn-j15-px");
    px.pushKV("kind", "RESERVE_PRICE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &px));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["financial_units"].get_str(), "atoms");
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["operational_units"].get_str(), "readiness");
    BOOST_CHECK(cr12_test::Body(r)["distinct_methodology"].isTrue());
    UniValue outage(UniValue::VOBJ);
    outage.pushKV("scenario_id", "scn-j15-ops");
    outage.pushKV("kind", "PROVIDER_OUTAGE");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &outage));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr12_test::Body(r)["distinct_methodology"].isTrue());
    e->PutResidentBase("base");
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-j15-frozen", tok)).status, 200);
    std::string code;
    const UniValue plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    UniValue ready;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, ready, code));
    BOOST_CHECK(ready["runtime_ready"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_j16_concurrency_and_idempotency)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue role(UniValue::VOBJ);
    role.pushKV("role", "TREASURY");
    role.pushKV("manifest_id", "role-j16");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &role));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const int64_t gen0 = cr12_test::Body(r)["generation"].getInt<int64_t>();
    UniValue ins(UniValue::VOBJ);
    ins.pushKV("instruction_id", "ins-j16");
    ins.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    for (int i = 0; i < 8; ++i) {
        r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &ins));
        BOOST_REQUIRE_EQUAL(r.status, 201);
        BOOST_CHECK_EQUAL(cr12_test::Body(r)["instruction_id"].get_str(), "ins-j16");
    }
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/ins-j16/translate", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string plan = cr12_test::Body(r)["draft_plan_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/ins-j16/translate", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["draft_plan_id"].get_str(), plan);
    UniValue changed(UniValue::VOBJ);
    changed.pushKV("instruction_id", "ins-j16");
    changed.pushKV("requested_action", "DRAFT_RESEARCH_COMMITMENT");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &changed))),
                      modelnet::HCP_ERR_CONFLICT);
    UniValue ov(UniValue::VOBJ);
    ov.pushKV("changed", true);
    ov.pushKV("body_override", "mutated");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions/ins-j16/translate", tok, &ov))),
                      modelnet::HCP_ERR_CONFLICT);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &role));
    BOOST_CHECK(cr12_test::Body(r)["generation"].getInt<int64_t>() > gen0);
    auto analytics = cr12_test::Tok(*e, cr12_test::AnalyticsScopes());
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j16-stale");
    alloc.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", analytics))),
                      modelnet::HCP_ERR_SCOPE);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "j16-apr");
    apr.pushKV("initiator_person_id", "person-initiator");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &apr));
    e->Cr11ExpirePerson("person-b");
    UniValue dec(UniValue::VOBJ);
    dec.pushKV("actor", "bob-session");
    dec.pushKV("decision", "APPROVE");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/j16-apr/decisions", tok, &dec))),
                      modelnet::HCP_ERR_SCOPE);
}

BOOST_AUTO_TEST_CASE(cr12_j17_scale_and_cancellation)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const auto t0 = std::chrono::steady_clock::now();
    BOOST_REQUIRE_EQUAL(e->Crl12LoadSynthetic(100000, "account-demo", "NONE"), 100000);
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
    BOOST_TEST_MESSAGE("J17 100k Crl12LoadSynthetic ms=" + std::to_string(ms));
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 100000);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/positions/pos-syn-0", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/positions/pos-syn-99999", tok)).status, 200);
    UniValue exp(UniValue::VOBJ);
    exp.pushKV("format", "JSONL");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &exp));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::Body(r)["total_rows"].getInt<int64_t>(), 100000);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/jobs/job-missing/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 404);
    UniValue adp(UniValue::VOBJ);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/adapters/validate", tok, &adp));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    HonestNotRun("J17", "in-flight job cancel: adapter/projection jobs commit immediately and do not return job_id");
    if (std::getenv("BTX_CR12_10M_LAB") == nullptr) {
        HonestNotRun("J17", "10m-row institutional lab: BTX_CR12_10M_LAB unset");
        return;
    }
    auto lab = cr12_test::Lab();
    const auto t1 = std::chrono::steady_clock::now();
    BOOST_REQUIRE_EQUAL(lab->Crl12LoadSynthetic(10000000, "account-demo", "NONE"), 10000000);
    const auto ms10 = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t1).count();
    BOOST_TEST_MESSAGE("J17 10m Crl12LoadSynthetic ms=" + std::to_string(ms10));
    BOOST_CHECK_EQUAL(lab->Crl12PositionCount(), 10000000);
}

BOOST_AUTO_TEST_CASE(cr12_j18_provider_exit_with_pending_capital)
{
    auto orig = MakeEngine("provider-j18-orig", true);
    auto neu = MakeEngine("provider-j18-new", false);
    auto tok = cr12_test::Tok(*orig);
    auto tok_n = cr12_test::Tok(*neu);
    UniValue bd(UniValue::VOBJ);
    bd.pushKV("role", "DISCOVERY");
    bd.pushKV("binding_id", "bind-j18-disc");
    auto r = orig->Handle(hcp_test::AuthReq(*orig, "POST", "/layer/bindings", tok, &bd));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue ba(UniValue::VOBJ);
    ba.pushKV("role", "PORTFOLIO_ANALYTICS");
    ba.pushKV("binding_id", "bind-j18-anal");
    BOOST_REQUIRE_EQUAL(orig->Handle(hcp_test::AuthReq(*orig, "POST", "/layer/bindings", tok, &ba)).status, 201);
    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "j18-child");
    alloc.pushKV("maximum_exposure", "10");
    r = orig->Handle(hcp_test::AuthReq(*orig, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr12_test::Body(r)["allocation_id"].get_str();
    r = orig->Handle(hcp_test::AuthReq(*orig, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = orig->Cr11LastExecutionId();
    BOOST_CHECK_EQUAL(orig->AccountHeld("account-demo"), 10);
    orig->Handle(hcp_test::AuthReq(*orig, "POST", "/layer/bindings/bind-j18-disc/revoke", tok));
    orig->Handle(hcp_test::AuthReq(*orig, "POST", "/layer/bindings/bind-j18-anal/revoke", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(orig->Handle(hcp_test::AuthReq(*orig, "GET", "/layer/bindings/bind-j18-disc", tok)))["status"].get_str(),
                      "REVOKED");
    orig->PutResidentBase("base");
    std::string code;
    BOOST_CHECK(orig->PlanLocal(hcp_test::kRecipe, code).exists("selected_source"));
    BOOST_REQUIRE_EQUAL(neu->Handle(hcp_test::AuthReq(*neu, "POST", "/capabilities/search", tok_n)).status, 200);
    r = orig->Handle(hcp_test::AuthReq(*orig, "GET", "/capital/executions/" + xid, tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    orig->Cr11MarkCrossCexAction("j18-child");
    UniValue alloc2(UniValue::VOBJ);
    alloc2.pushKV("client_operation_id", "j18-replay");
    alloc2.pushKV("maximum_exposure", "10");
    r = orig->Handle(hcp_test::AuthReq(*orig, "POST", "/capital/allocations", tok, &alloc2));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid2 = cr12_test::Body(r)["allocation_id"].get_str();
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("cross_cex_action_id", "j18-child");
    r = orig->Handle(hcp_test::AuthReq(*orig, "POST", "/capital/allocations/" + aid2 + "/execute", tok, &ex));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(r), modelnet::HCP_ERR_CROSS_CEX);
    BOOST_CHECK_EQUAL(orig->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr12_j19_migration_and_rollback)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok)).status, 201);
    UniValue v(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string iid = cr12_test::Body(r)["import_id"].get_str();
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + iid + "/commit", tok)).status, 200);
    UniValue row(UniValue::VOBJ);
    row.pushKV("observation_id", "pos-j19");
    row.pushKV("source", "mig");
    row.pushKV("generation", "1");
    row.pushKV("sequence", "1");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &row)).status, 201);
    UniValue v4(UniValue::VOBJ);
    v4.pushKV("package_core_version", 4);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &v4))),
                      modelnet::HCP_ERR_CORE_V4);
    const int64_t native = e->Crl12NativeAvailable("account-demo");
    e->Crl12SetEnabled(false);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok)).status, 201);
    BOOST_CHECK_EQUAL(e->Crl12NativeAvailable("account-demo"), native);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr12_j20_neutral_commercial_demonstration)
{
    auto venue = MakeEngine("provider-j20-venue", true);
    auto spec = MakeEngine("provider-j20-anal", true);
    auto green = MakeEngine("provider-j20-green", false);
    auto tok_v = cr12_test::Tok(*venue);
    auto tok_s = cr12_test::Tok(*spec, cr12_test::AnalyticsScopes());
    auto tok_g = cr12_test::Tok(*green);
    auto tok_sa = cr12_test::Tok(*spec);
    for (auto* e : {venue.get(), spec.get(), green.get()}) {
        auto tok = cr12_test::Tok(*e);
        auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok));
        BOOST_REQUIRE_EQUAL(r.status, 200);
        BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_LAYER_EXTENSION);
        BOOST_CHECK(cr12_test::Body(r)["not_inferred_from_provider_name"].isTrue());
        r = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/conformance/self-j20", tok));
        BOOST_CHECK(cr12_test::Body(r)["not_central_certification"].isTrue());
        auto h = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
        BOOST_CHECK_EQUAL(cr12_test::Json(h)["automatic_spend_atoms"].getInt<int64_t>(), 0);
        BOOST_CHECK(cr12_test::Json(h)["cognitive_reserve_layer"].isTrue());
    }
    UniValue full(UniValue::VOBJ);
    full.pushKV("role", "CUSTODY");
    BOOST_REQUIRE_EQUAL(venue->Handle(hcp_test::AuthReq(*venue, "POST", "/layer/roles", tok_v, &full)).status, 201);
    UniValue anal(UniValue::VOBJ);
    anal.pushKV("role", "PORTFOLIO_ANALYTICS");
    auto r = spec->Handle(hcp_test::AuthReq(*spec, "POST", "/layer/roles", tok_sa, &anal));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(!cr12_test::Body(r).exists("invented_aum"));
    UniValue gre(UniValue::VOBJ);
    gre.pushKV("role", "DISCOVERY");
    BOOST_REQUIRE_EQUAL(green->Handle(hcp_test::AuthReq(*green, "POST", "/layer/roles", tok_g, &gre)).status, 201);
    UniValue ast(UniValue::VOBJ);
    ast.pushKV("label", "external-observed");
    ast.pushKV("kind", "FINANCIAL");
    r = venue->Handle(hcp_test::AuthReq(*venue, "POST", "/institutional/assets", tok_v, &ast));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_INSTITUTIONAL_ASSET);
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("metric_kind", "AUM");
    r = spec->Handle(hcp_test::AuthReq(*spec, "POST", "/institutional/projections", tok_sa, &pr));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_PORTFOLIO_PROJECTION);
    const std::string prid = cr12_test::Body(r)["projection_id"].get_str();
    BOOST_CHECK_EQUAL(spec->Handle(hcp_test::AuthReq(*spec, "GET", "/institutional/projections/" + prid, tok_s)).status, 200);
    BOOST_CHECK_EQUAL(green->Handle(hcp_test::AuthReq(*green, "POST", "/capabilities/search", tok_g)).status, 200);
    BOOST_CHECK_NE(venue->Cfg().provider_id, spec->Cfg().provider_id);
    BOOST_CHECK_NE(spec->Cfg().provider_id, green->Cfg().provider_id);
}

BOOST_AUTO_TEST_SUITE_END()
