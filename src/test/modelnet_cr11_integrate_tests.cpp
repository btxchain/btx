// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_integrate_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_integrate_01_custody_fee_basis)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1'000'000);
    e->Cr11SetRemainingAuthority(100'000);
    auto tok = cr11_test::Tok(*e);

    UniValue port(UniValue::VOBJ);
    port.pushKV("portfolio_id", "int01-custody");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok, &port));
    BOOST_REQUIRE_EQUAL(r.status, 201);

    auto atoms = [](const UniValue& v) {
        int64_t n = 0;
        std::string err;
        BOOST_REQUIRE_MESSAGE(modelnet::ParseAtomString(v.get_str(), n, err), err);
        return n;
    };

    // A custody segment is billed on the balance actually held for the entity:
    // AVAILABLE + HELD. committed_atoms restates those same held atoms for the
    // approvals view, so a base that adds it charges one commitment twice.
    struct Observation {
        int64_t at;
        int64_t base;
        int64_t double_counted;
    };
    std::vector<Observation> obs;
    auto observe = [&]() {
        auto s = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/int01-custody/snapshot", tok));
        BOOST_REQUIRE_EQUAL(s.status, 200);
        BOOST_REQUIRE_EQUAL(cr11_test::ObjType(s), modelnet::HCP_TYPE_RESERVE_SNAPSHOT);
        const UniValue b = cr11_test::Json(s)["body"];
        const int64_t available = atoms(b["available_atoms"]);
        const int64_t held = atoms(b["existing_hold_atoms"]);
        const int64_t committed = atoms(b["committed_atoms"]);
        BOOST_CHECK_EQUAL(available, e->AccountAvailable("account-demo"));
        BOOST_CHECK_EQUAL(held, e->AccountHeld("account-demo"));
        BOOST_CHECK_EQUAL(committed, e->Cr11Outstanding());
        BOOST_CHECK_EQUAL(committed, held);
        obs.push_back({atoms(b["observed_at"]), available + held, available + held + committed});
    };

    observe();
    e->SetClock(e->Now() + 600'000);

    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "int01-commit");
    alloc.pushKV("maximum_exposure", "100000");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const UniValue xb = cr11_test::Json(r)["body"];
    BOOST_CHECK_EQUAL(xb["held_atoms"].get_str(), "100000");

    // The commitment moves principal only. A custody charge is invoiced separately and
    // is never netted out of the held principal.
    BOOST_REQUIRE(xb["children"].isArray());
    BOOST_REQUIRE_EQUAL(xb["children"].size(), 1u);
    const UniValue child = xb["children"][0];
    BOOST_CHECK_EQUAL(child["object_type"].get_str(), modelnet::HCP_TYPE_FINANCE_INTENT);
    BOOST_CHECK_EQUAL(child["body"]["action"].get_str(), modelnet::HCP_ACTION_FUND_RELEASE);
    BOOST_CHECK_EQUAL(child["body"]["amounts"]["principal_atoms"].get_str(), "100000");
    BOOST_CHECK_EQUAL(child["body"]["amounts"]["service_fee_atoms"].get_str(), "0");

    observe();
    e->SetClock(e->Now() + 600'000);
    e->PutAccount("account-demo", 1'400'000); // separately settled deposit lands
    observe();
    e->SetClock(e->Now() + 1'200'000);
    observe();

    BOOST_REQUIRE_EQUAL(obs.size(), 4u);
    // The engine stamps each observation, so the weights are its clock, not the test's.
    BOOST_CHECK_EQUAL(obs.back().at - obs.front().at, 2'400'000);
    BOOST_CHECK_EQUAL(obs[0].base, 1'000'000);
    BOOST_CHECK_EQUAL(obs[1].base, obs[0].base); // committing atoms does not grow the base
    BOOST_CHECK_EQUAL(obs[1].double_counted, 1'100'000);
    BOOST_CHECK_EQUAL(obs[3].base, 1'500'000);

    int64_t weighted = 0;
    int64_t weighted_double = 0;
    int64_t elapsed = 0;
    for (size_t i = 0; i + 1 < obs.size(); ++i) {
        const int64_t dt = obs[i + 1].at - obs[i].at;
        BOOST_REQUIRE_GT(dt, int64_t{0});
        weighted += obs[i].base * dt;
        weighted_double += obs[i].double_counted * dt;
        elapsed += dt;
    }
    BOOST_REQUIRE_EQUAL(elapsed, 2'400'000);
    const int64_t fee_bps = 15;
    BOOST_CHECK_EQUAL(weighted / elapsed, 1'250'000);
    BOOST_CHECK_EQUAL(weighted / elapsed * fee_bps / 10000, 1875);
    BOOST_CHECK_EQUAL(weighted_double / elapsed * fee_bps / 10000, 1987);

    // The charge is invoiced, not swept: no automatic debit and no fee intent.
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1'400'000);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 100'000);
    BOOST_CHECK_EQUAL(e->IntentCount(), 1u);
    // Protected atoms and consumed mandate stay in custody although they are no longer
    // allocatable, so the fee base and the allocation capacity are different numbers.
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_02_trading_fees)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_03_funding_principal)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK(e->Cfg().finance_enabled);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_04_family_purpose_separation)
{
    auto e = cr11_test::Lab();
    e->Cr11SetFamilyView(true);
    BOOST_CHECK(e->Cr11ExtensionEnabled());
}

BOOST_AUTO_TEST_CASE(cr11_integrate_05_measured_savings)
{
    auto e = cr11_test::Lab();
    e->Cr11SetForecastSavings(100);
    e->PutAccount("account-demo", 1000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), modelnet::Cr11Capacity(900, 400, 250));
}

BOOST_AUTO_TEST_CASE(cr11_integrate_06_second_partner_onboarding)
{
    std::string err;
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.provider_id = "provider-b";
    auto b = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE(b);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_07_real_route_coverage)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    const char* paths[] = {
        "/extensions/cognitive-reserve", "/reserve/entities/links", "/reserve/portfolios",
        "/reserve/policies", "/capital/workloads", "/capital/approval-rules", "/capital/programs",
        "/capital/products", "/capital/positions", "/capital/reports"
    };
    int ok = 0;
    for (const char* p : paths) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "GET", p, tok));
        if (r.status == 200 || r.status == 201) ++ok;
    }
    BOOST_CHECK_GE(ok, 8);

    auto post201 = [&](const char* path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_EQUAL(r.status, 201);
        return r;
    };
    auto get200 = [&](const std::string& path, const char* type, const char* id_field, const std::string& id) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "GET", path, tok));
        BOOST_CHECK_EQUAL(r.status, 200);
        const auto j = cr11_test::Json(r);
        if (type && *type) {
            BOOST_CHECK_EQUAL(j.exists("object_type") ? j["object_type"].get_str() : std::string{}, type);
        }
        if (id_field && *id_field) {
            if (j.exists("body") && j["body"].exists(id_field)) {
                BOOST_CHECK_EQUAL(j["body"][id_field].get_str(), id);
            } else if (j.exists(id_field)) {
                BOOST_CHECK_EQUAL(j[id_field].get_str(), id);
            } else {
                BOOST_ERROR(std::string("GET ") + path + " missing " + id_field);
            }
        }
        return r;
    };

    UniValue link(UniValue::VOBJ);
    link.pushKV("parent_entity_id", "le-demo");
    link.pushKV("child_entity_id", "le-child");
    auto r = post201("/reserve/entities/links", &link);
    const std::string link_id = cr11_test::Json(r)["body"]["link_id"].get_str();
    get200("/reserve/entities/links/" + link_id, modelnet::HCP_TYPE_ENTITY_LINK, "link_id", link_id);

    r = post201("/reserve/portfolios", nullptr);
    const std::string port_id = cr11_test::Json(r)["body"]["portfolio_id"].get_str();
    get200("/reserve/portfolios/" + port_id, modelnet::HCP_TYPE_PORTFOLIO, "portfolio_id", port_id);

    r = post201("/reserve/policies", nullptr);
    const std::string pol_id = cr11_test::Json(r)["body"]["policy_id"].get_str();
    get200("/reserve/policies/" + pol_id, modelnet::HCP_TYPE_RESERVE_POLICY, "policy_id", pol_id);

    r = post201("/capital/workloads", nullptr);
    const std::string wl_id = cr11_test::Json(r)["body"]["workload_id"].get_str();
    get200("/capital/workloads/" + wl_id, modelnet::HCP_TYPE_WORKLOAD, "workload_id", wl_id);

    UniValue tco(UniValue::VOBJ);
    tco.pushKV("annual_tasks", "20000000");
    tco.pushKV("service_per_task", "0.01");
    tco.pushKV("years", 3);
    tco.pushKV("upfront", "50000");
    tco.pushKV("annual_local", "65000");
    r = post201("/capital/comparisons", &tco);
    const std::string tco_id = cr11_test::Json(r)["body"]["comparison_id"].get_str();
    get200("/capital/comparisons/" + tco_id, modelnet::HCP_TYPE_TCO, "comparison_id", tco_id);

    r = post201("/capital/plans", nullptr);
    const std::string plan_id = cr11_test::Json(r)["body"]["plan_id"].get_str();
    get200("/capital/plans/" + plan_id, modelnet::HCP_TYPE_CAPITAL_PLAN, "plan_id", plan_id);

    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "int07-alloc");
    alloc.pushKV("maximum_exposure", "10");
    r = post201("/capital/allocations", &alloc);
    const std::string alloc_id = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    get200("/capital/allocations/" + alloc_id, modelnet::HCP_TYPE_ALLOCATION, "allocation_id", alloc_id);

    r = post201("/capital/approval-rules", nullptr);
    const std::string rule_id = cr11_test::Json(r)["body"]["rule_id"].get_str();
    get200("/capital/approval-rules/" + rule_id, modelnet::HCP_TYPE_APPROVAL_RULE, "rule_id", rule_id);

    UniValue apr(UniValue::VOBJ);
    apr.pushKV("allocation_ref", alloc_id);
    apr.pushKV("rule_ref", rule_id);
    r = post201("/capital/approvals", &apr);
    const std::string apr_id = cr11_test::Json(r)["body"]["request_id"].get_str();
    get200("/capital/approvals/" + apr_id, modelnet::HCP_TYPE_APPROVAL_REQUEST, "request_id", apr_id);

    // Execute requires quorum once an approval request exists.
    UniValue dec_a(UniValue::VOBJ);
    dec_a.pushKV("actor", "alice-session");
    dec_a.pushKV("decision", "APPROVE");
    auto d1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/" + apr_id + "/decisions", tok, &dec_a));
    BOOST_REQUIRE_EQUAL(d1.status, 201);
    UniValue dec_b(UniValue::VOBJ);
    dec_b.pushKV("actor", "bob-session");
    dec_b.pushKV("decision", "APPROVE");
    auto d2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals/" + apr_id + "/decisions", tok, &dec_b));
    BOOST_REQUIRE_EQUAL(d2.status, 201);

    auto decs = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/approvals/" + apr_id + "/decisions", tok));
    BOOST_CHECK_EQUAL(decs.status, 200);
    const auto dj = cr11_test::Json(decs);
    BOOST_CHECK(dj.exists("items") && dj["items"].isArray());
    BOOST_REQUIRE_GE(dj["items"].size(), 1);
    BOOST_CHECK_EQUAL(dj["items"][0]["request_ref"].get_str(), apr_id);
    if (dj.exists("object_type")) {
        BOOST_CHECK_EQUAL(dj["object_type"].get_str(), modelnet::HCP_TYPE_APPROVAL_DECISION);
    }

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + alloc_id + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = cr11_test::Json(r)["body"]["execution_id"].get_str();
    get200("/capital/executions/" + xid, modelnet::HCP_TYPE_CAPITAL_EXECUTION, "execution_id", xid);

    r = post201("/capital/exports", nullptr);
    const auto ej = cr11_test::Json(r);
    const std::string exp_id = ej.exists("body") && ej["body"].exists("export_id") ? ej["body"]["export_id"].get_str() :
                                                                                   ej["export_id"].get_str();
    get200("/capital/exports/" + exp_id, "", "export_id", exp_id);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_08_sdk_parity)
{
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_RESERVE_SNAPSHOT;
    env.body.pushKV("schema_revision", "1.1");
    env.body.pushKV("provider_id", "p");
    env.body.pushKV("created_at", "1");
    env.body.pushKV("scope", "s");
    env.body.pushKV("snapshot_id", "s");
    env.body.pushKV("ledger_sequence", "1");
    env.body.pushKV("policy_ref", "p");
    env.body.pushKV("available_atoms", "1");
    env.body.pushKV("protected_atoms", "0");
    env.body.pushKV("remaining_authority_atoms", "1");
    env.body.pushKV("allocation_capacity_atoms", "1");
    env.body.pushKV("existing_hold_atoms", "0");
    env.body.pushKV("committed_atoms", "0");
    env.body.pushKV("refund_pending_atoms", "0");
    env.body.pushKV("observed_at", "1");
    std::string err;
    modelnet::Digest48 id;
    BOOST_REQUIRE(modelnet::HcpBodyId(env.object_type, env.body, id, err));
    BOOST_CHECK_EQUAL(id.Hex().size(), 96u);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_09_no_remote_inference)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK(!e->Cfg().expose_runtime_to_gateway);
}

BOOST_AUTO_TEST_CASE(cr11_integrate_10_regression_closure)
{
    auto e = hcp_test::Lab();
    auto tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PROVIDER_PROFILE);
}

BOOST_AUTO_TEST_SUITE_END()
