// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_product_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_product_01_eligibility)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PRODUCT_OFFER);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["product_id"].get_str(), "prod-demo");
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("trade_id"));
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("loan_id"));
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    auto read = hcp_test::Token(*e, {"products:read", "capital:read"});
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/products/prod-demo/referral", read));
    BOOST_CHECK_EQUAL(r.status, 401);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_SCOPE);
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/products/prod-demo/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 404);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_product_02_referral_is_not_execution)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    const int64_t avail = e->AccountAvailable("account-demo");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/products/prod-demo/referral", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK(cr11_test::Json(r)["not_a_debit"].isTrue());
    BOOST_CHECK(!cr11_test::Json(r).exists("execution_id"));
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), avail);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_product_03_actual_rights)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(r.body.find("BTX-created security") == std::string::npos);
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_PRODUCT_OFFER);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["title"].get_str(), "listed-note");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["provider_id"].get_str(), e->Cfg().provider_id);
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("btx_security_id"));
    BOOST_CHECK(r.body.find("BTX-created security") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_product_04_fee_state)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["committed_atoms"].get_str(), "0");
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("referral_fee_atoms"));
    BOOST_CHECK(!cr11_test::Json(r)["body"].exists("execution_fee_atoms"));
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_product_05_encumbrance)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 1000);
    e->Cr11SetEncumbered(700);
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), 300);

    auto tok = cr11_test::Tok(*e);
    UniValue over(UniValue::VOBJ);
    over.pushKV("client_operation_id", "enc-over");
    over.pushKV("maximum_exposure", "301");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &over));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 403);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    UniValue ok(UniValue::VOBJ);
    ok.pushKV("client_operation_id", "enc-ok");
    ok.pushKV("maximum_exposure", "300");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &ok));
    const std::string aid2 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 300);
}

BOOST_AUTO_TEST_CASE(cr11_product_06_firm_quote_expiry)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 100000);
    auto tok = cr11_test::Tok(*e);
    auto q = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok));
    BOOST_REQUIRE_EQUAL(q.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(q), modelnet::HCP_TYPE_FUNDING_QUOTE);
    BOOST_CHECK_EQUAL(cr11_test::Json(q)["body"]["quote_kind"].get_str(), "FIRM");
    const std::string qid = cr11_test::Json(q)["body"]["quote_id"].get_str();
    e->ExpireQuote(qid);

    UniValue amounts(UniValue::VOBJ);
    amounts.pushKV("principal_atoms", "10");
    amounts.pushKV("network_fee_cap_atoms", "0");
    amounts.pushKV("service_fee_atoms", "0");
    amounts.pushKV("tax_atoms", "0");
    amounts.pushKV("max_total_debit_atoms", "10");
    UniValue body(UniValue::VOBJ);
    body.pushKV("quote_id", qid);
    body.pushKV("client_operation_id", "prod06-expired");
    body.pushKV("amounts", amounts);
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_CHECK_EQUAL(created.status, 400);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(created), modelnet::HCP_ERR_QUOTE_EXPIRED);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->IntentCount(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_product_07_data_sharing_consent)
{
    auto e = cr11_test::Lab();
    e->SetPrivateKv("customer-deployment-kv");
    e->SetPrivatePrompt("customer-prompt");
    e->PutSentinel("tok", "CEX-TOKEN");
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/products/prod-demo/referral", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const UniValue j = cr11_test::Json(r);
    BOOST_CHECK(j.exists("referral_id"));
    BOOST_CHECK(j["not_a_debit"].isTrue());
    BOOST_CHECK_EQUAL(j["product_id"].get_str(), "prod-demo");
    BOOST_CHECK(!j.exists("kv"));
    BOOST_CHECK(!j.exists("prompt"));
    BOOST_CHECK(!j.exists("access_token"));
    BOOST_CHECK(r.body.find("customer-deployment-kv") == std::string::npos);
    BOOST_CHECK(r.body.find("CEX-TOKEN") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_product_08_adapter_outage)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    const int64_t cap0 = e->Cr11CapacityOf("account-demo");
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
    BOOST_CHECK(e->ConnectorStatus()["provider_reachable"].isFalse());

    auto prof = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(prof.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(prof), modelnet::HCP_TYPE_PROVIDER_PROFILE);
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(health.status, 200);
    auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(snap.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(snap)["body"]["allocation_capacity_atoms"].get_str(), "250");
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), cap0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK(!e->ProviderReachable());
}

BOOST_AUTO_TEST_CASE(cr11_product_09_existing_engine)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->Cfg().custody_backend, modelnet::HCP_CUSTODY_BTX_NATIVE);
    BOOST_CHECK(e->Cfg().finance_enabled);
    e->PutAccount("account-demo", 100000);
    auto tok = cr11_test::Tok(*e);
    auto q = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok));
    BOOST_REQUIRE_EQUAL(q.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(q), modelnet::HCP_TYPE_FUNDING_QUOTE);
    BOOST_CHECK_EQUAL(cr11_test::Json(q)["body"]["quote_kind"].get_str(), "FIRM");
    BOOST_CHECK_EQUAL(cr11_test::Json(q)["body"]["action"].get_str(), modelnet::HCP_ACTION_FUND_RELEASE);
    BOOST_CHECK(cr11_test::Json(q)["body"]["amounts"].exists("principal_atoms"));

    UniValue otc(UniValue::VOBJ);
    otc.pushKV("client_operation_id", "prod09-otc");
    otc.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &otc));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(cr11_test::ObjType(r), modelnet::HCP_TYPE_CAPITAL_EXECUTION);
    BOOST_CHECK(!e->Cr11LastChildIntent().empty());
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_product_10_no_phantom_yield)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/x/snapshot", tok));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    BOOST_CHECK(r.body.find("staking") == std::string::npos);
    BOOST_CHECK(r.body.find("rehypothecation") == std::string::npos);
    BOOST_CHECK(cr11_test::Json(r)["body"]["nav_merged"].isFalse());
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["available_atoms"].get_str(), "1000");
    BOOST_CHECK_EQUAL(cr11_test::Json(r)["body"]["committed_atoms"].get_str(), "0");
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(health)["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
