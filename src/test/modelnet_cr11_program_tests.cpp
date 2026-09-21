// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_program_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_program_01_outcome_defined_objective)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue wl(UniValue::VOBJ);
    wl.pushKV("workload_id", "prog01-wl");
    wl.pushKV("evidence_minimum", "LOCAL_OBSERVATION");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/workloads", tok, &wl));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/workloads/prog01-wl", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["evidence_minimum"].get_str(), "LOCAL_OBSERVATION");

    UniValue body(UniValue::VOBJ);
    body.pushKV("program_id", "prog01");
    body.pushKV("title", "eval-threshold");
    body.pushKV("model_brand", "acme-llm");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESEARCH_PROGRAM);
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent_sponsor_lots"].isTrue());
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["title"].get_str(), "eval-threshold");
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("model_brand"));

    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog01", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["program_id"].get_str(), "prog01");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["title"].get_str(), "eval-threshold");
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("model_brand"));
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_program_02_independent_sponsors)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog02");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);

    UniValue a(UniValue::VOBJ);
    a.pushKV("legal_entity_id", "le-sponsor-a");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog02/memberships", tok, &a));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PROGRAM_MEMBERSHIP);
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent"].isTrue());
    const std::string lot_a = cr11_test::Json(r)["body"]["lot_id"].get_str();
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["member_entity"].get_str(), "le-sponsor-a");

    UniValue b(UniValue::VOBJ);
    b.pushKV("legal_entity_id", "le-sponsor-b");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog02/memberships", tok, &b));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent"].isTrue());
    const std::string lot_b = cr11_test::Json(r)["body"]["lot_id"].get_str();
    BOOST_CHECK_NE(lot_a, lot_b);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["member_entity"].get_str(), "le-sponsor-b");

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog02/commitments", tok));
    BOOST_CHECK(cr11_test::Json(r)["prepared"].isTrue());
    BOOST_CHECK(!cr11_test::Json(r)["executed"].isTrue());
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_program_03_membership_not_consent)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog03");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog03/memberships", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog03/commitments", tok));
    BOOST_CHECK(cr11_test::Json(r)["prepared"].isTrue());
    BOOST_CHECK(!cr11_test::Json(r)["executed"].isTrue());
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);

    UniValue alloc(UniValue::VOBJ);
    alloc.pushKV("client_operation_id", "prog03-debit");
    alloc.pushKV("maximum_exposure", "10");
    alloc.pushKV("capital_plan_ref", "prog03");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &alloc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "prog03-rule");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approval-rules", tok, &rule));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "prog03-apr");
    apr.pushKV("allocation_ref", aid);
    apr.pushKV("rule_ref", "prog03-rule");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/approvals", tok, &apr));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_program_04_no_invented_pool)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog04");
    prog.pushKV("title", "aggregate-budget");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(r.body.find("pooled escrow") == std::string::npos);
    BOOST_CHECK(r.body.find("transferable security") == std::string::npos);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog04", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("escrow_atoms"));
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("pooled_principal"));
    BOOST_CHECK(cr11_test::Json(r)["body"]["independent_sponsor_lots"].isTrue());
    auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(snap)["body"]["committed_atoms"].get_str(), "0");
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_CASE(cr11_program_05_native_evaluation_authority)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog05");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_RESERVE_REPORT);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs/prog05/award", tok));
    BOOST_CHECK_EQUAL(r.status, 404);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    e->SetObserverAvailable(false);
    const UniValue man = e->GoLiveManifest();
    BOOST_CHECK(!man.empty());
    BOOST_CHECK(!man["proven"]["FUNDING"].isTrue());
    BOOST_REQUIRE(man["not_run"].isArray());
    BOOST_CHECK_GE(man["not_run"].size(), 1u);
    BOOST_CHECK_EQUAL(man["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_program_06_evidence_privacy)
{
    auto e = cr11_test::Lab();
    e->SetPrivateKv("sponsor-secret-kv");
    e->SetPrivatePrompt("sponsor-secret-prompt");
    auto tok = cr11_test::Tok(*e);
    UniValue prog(UniValue::VOBJ);
    prog.pushKV("program_id", "prog06");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/programs", tok, &prog));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog06", tok));
    BOOST_CHECK(r.body.find("sponsor-secret-kv") == std::string::npos);
    BOOST_CHECK(r.body.find("sponsor-secret-prompt") == std::string::npos);

    auto reader = hcp_test::Token(*e, {"capital:read", "catalog:read"});
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog06", reader));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(r.body.find("sponsor-secret-kv") == std::string::npos);

    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub.write().find("sponsor-secret-kv") == std::string::npos);
    BOOST_CHECK(pub.write().find("sponsor-secret-prompt") == std::string::npos);
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_export"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr11_program_07_refund_terms)
{
    auto e = cr11_test::Lab();
    e->Cr11SetRefundReplenish(false);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    e->PutAccount("account-demo", 1000);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "prog07-lot");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 10);
    const std::string xid = e->Cr11LastExecutionId();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 10);

    UniValue again(UniValue::VOBJ);
    again.pushKV("client_operation_id", "prog07-reuse");
    again.pushKV("maximum_exposure", "10000");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &again));
    const std::string aid2 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_program_08_terms_revision)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto post = [&](const std::string& path, const UniValue* body) {
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", path, tok, body));
        BOOST_REQUIRE_MESSAGE(r.status == 201, path + " -> " + r.body);
        return cr11_test::Json(r);
    };

    // Terms v1: a published objective and the authority ceiling it was funded under.
    UniValue terms1(UniValue::VOBJ);
    terms1.pushKV("policy_id", "prog08-terms-1");
    terms1.pushKV("lifetime_cap_atoms", "200");
    BOOST_CHECK_EQUAL(post("/reserve/policies", &terms1)["body"]["generation"].get_str(), "1");
    UniValue v1(UniValue::VOBJ);
    v1.pushKV("program_id", "prog08-v1");
    v1.pushKV("title", "objective-v1");
    post("/capital/programs", &v1);

    UniValue fund1(UniValue::VOBJ);
    fund1.pushKV("client_operation_id", "prog08-fund-v1");
    fund1.pushKV("maximum_exposure", "150");
    fund1.pushKV("capital_plan_ref", "prog08-v1");
    const std::string aid1 = post("/capital/allocations", &fund1)["body"]["allocation_id"].get_str();
    post("/capital/allocations/" + aid1 + "/execute", nullptr);
    BOOST_REQUIRE_EQUAL(e->Cr11LifetimeSpent(), 150);

    // The committee file raised for the v1 objective pins the generation it was raised under.
    UniValue rule(UniValue::VOBJ);
    rule.pushKV("rule_id", "prog08-rule");
    post("/capital/approval-rules", &rule);
    UniValue apr(UniValue::VOBJ);
    apr.pushKV("request_id", "prog08-approval");
    apr.pushKV("allocation_ref", aid1);
    apr.pushKV("rule_ref", "prog08-rule");
    BOOST_CHECK_EQUAL(post("/capital/approvals", &apr)["body"]["policy_generation"].get_str(), "1");

    // Terms revision: a new objective record, plus a renewed policy generation that
    // tightens the lifetime ceiling down to what is already committed.
    UniValue v2(UniValue::VOBJ);
    v2.pushKV("program_id", "prog08-v2");
    v2.pushKV("title", "objective-v2");
    post("/capital/programs", &v2);
    UniValue terms2(UniValue::VOBJ);
    terms2.pushKV("policy_id", "prog08-terms-2");
    terms2.pushKV("lifetime_cap_atoms", "150");
    BOOST_CHECK_EQUAL(post("/reserve/policies", &terms2)["body"]["generation"].get_str(), "2");

    // The revision does not rewrite the objective that was already funded.
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog08-v1", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["title"].get_str(), "objective-v1");
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/programs/prog08-v2", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["title"].get_str(), "objective-v2");

    // A decision filed after the revision still records the generation of its request,
    // so v1 consent is never recorded as consent to the renewed terms.
    UniValue dec_a(UniValue::VOBJ);
    dec_a.pushKV("actor", "alice-session");
    dec_a.pushKV("decision", "APPROVE");
    const UniValue filed = post("/capital/approvals/prog08-approval/decisions", &dec_a);
    BOOST_CHECK_EQUAL(filed["body"]["policy_generation"].get_str(), "1");
    BOOST_CHECK_EQUAL(filed["body"]["person"].get_str(), "person-a");

    // Funding the revised objective on the old authority: the renewed ceiling leaves no
    // room, and the refusal moves nothing.
    UniValue fund2(UniValue::VOBJ);
    fund2.pushKV("client_operation_id", "prog08-fund-v2");
    fund2.pushKV("maximum_exposure", "10");
    fund2.pushKV("capital_plan_ref", "prog08-v2");
    const std::string aid2 = post("/capital/allocations", &fund2)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 150);
    BOOST_CHECK_EQUAL(e->Cr11Outstanding(), 150);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 150);

    // Renewed authority is not renewed approval: the single carried-over decision does
    // not meet the distinct-person quorum.
    UniValue terms3(UniValue::VOBJ);
    terms3.pushKV("policy_id", "prog08-terms-3");
    terms3.pushKV("lifetime_cap_atoms", "300");
    BOOST_CHECK_EQUAL(post("/reserve/policies", &terms3)["body"]["generation"].get_str(), "3");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_QUORUM);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 150);

    // Exact renewed terms and authority: a second distinct person, then the revised
    // objective funds against the renewed ceiling only.
    UniValue dec_b(UniValue::VOBJ);
    dec_b.pushKV("actor", "bob-session");
    dec_b.pushKV("decision", "APPROVE");
    post("/capital/approvals/prog08-approval/decisions", &dec_b);
    BOOST_CHECK_EQUAL(post("/capital/allocations/" + aid2 + "/execute", nullptr)["body"]["held_atoms"].get_str(), "10");
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 160);
    BOOST_CHECK_EQUAL(e->Cr11Outstanding(), 160);
}

BOOST_AUTO_TEST_CASE(cr11_program_09_supplier_proceeds)
{
    auto e = cr11_test::Lab();
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    e->PutAccount("account-demo", 1000);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "prog09-claim");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["committed_atoms"].get_str(), "10");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["existing_hold_atoms"].get_str(), "10");
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("nominal_bounty_atoms"));
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("claimed_bounty_size"));
    BOOST_CHECK(cr11_test::Json(r)["body"]["nav_merged"].isFalse());

    const UniValue analytics = e->AnalyticsView();
    BOOST_CHECK(analytics["cross_tenant"].isFalse());
    BOOST_CHECK(analytics.write().find("nominal_bounty") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_program_10_replicated_deployment)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    const std::string recipe(96, '3');
    std::set<std::string> ids;
    for (int i = 0; i < 32; ++i) {
        UniValue pos(UniValue::VOBJ);
        pos.pushKV("position_id", "prog10-" + std::to_string(i));
        pos.pushKV("recipe_id", recipe);
        pos.pushKV("rights_ref", "rights-shared");
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &pos));
        BOOST_REQUIRE_EQUAL(r.status, 201);
        BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPABILITY_POSITION);
        BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["rights_ref"].get_str(), "rights-shared");
        ids.insert(cr11_test::Json(r)["body"]["position_id"].get_str());
    }
    BOOST_CHECK_EQUAL(ids.size(), 32u);
    auto listed = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/positions", tok));
    BOOST_CHECK(cr11_test::Json(listed)["nav_merged"].isFalse());
    BOOST_CHECK_EQUAL(cr11_test::Json(listed)["items"].size(), 32u);

    UniValue merge(UniValue::VOBJ);
    merge.pushKV("position_id", "prog10-merge");
    merge.pushKV("merge_nav", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/positions", tok, &merge));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_NAV_MERGE);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_SUITE_END()
