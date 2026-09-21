// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_local_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_local_01_walletless_acquisition)
{
    auto e = hcp_test::Lab(false);
    BOOST_CHECK(e->Cfg().walletless);
    BOOST_CHECK(!e->Cfg().finance_enabled);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    auto tok = cr11_test::Tok(*e);
    auto prof = e->Handle(hcp_test::AuthReq(*e, "GET", "/profile", tok));
    BOOST_CHECK_EQUAL(prof.status, 200);
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(health.status, 200);
    BOOST_CHECK(cr11_test::Json(health)["walletless"].isTrue());
    BOOST_CHECK(cr11_test::Json(health)["finance"].isFalse());
    BOOST_CHECK(cr11_test::Json(health)["cognitive_reserve"].isFalse());
    auto port = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/portfolios", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(port), modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    auto quote = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok));
    BOOST_CHECK_GE(quote.status, 400);
    auto pkg = e->Handle(hcp_test::AuthReq(*e, "GET", std::string("/packages/") + hcp_test::kCore, tok));
    BOOST_CHECK_EQUAL(pkg.status, 200);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_local_02_locality_reuse)
{
    auto e = cr11_test::Lab();
    e->PutResidentBase("base");
    e->PutLanSource("adapter", 5);
    e->PutInternetSource("hint", 500);
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(code.empty());
    BOOST_CHECK(!plan["base_redownload"].isTrue());
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
    BOOST_CHECK(!plan["fixed_rank_hierarchy"].isTrue());
    const std::string src = plan["selected_source"].get_str();
    BOOST_CHECK(src.find("internet:") == std::string::npos);
    BOOST_CHECK(src == "resident" || src.find("lan:") == 0);
    BOOST_CHECK_LT(plan["ttc_ms"].getInt<int64_t>(), 500);
}

BOOST_AUTO_TEST_CASE(cr11_local_03_owner_grant)
{
    auto e = cr11_test::Lab();
    e->RevokeLocalGrant();
    std::string code, err;
    const UniValue acc = e->AcceptHandoff(
        hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code,
        err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_LOCAL_GRANT_REQUIRED);
    BOOST_CHECK(!acc.exists("handoff_id") || acc.empty());
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_local_04_cfo_not_os_authority)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("shell", "rm");
    body.pushKV("client_operation_id", "cfo-os");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(r.status, 400);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), "FORBIDDEN_FIELD");
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    std::string ferr;
    UniValue forbidden(UniValue::VOBJ);
    forbidden.pushKV("shell", "rm");
    BOOST_CHECK(!modelnet::HcpRejectForbiddenFields(forbidden, ferr));
    BOOST_CHECK_EQUAL(ferr, "FORBIDDEN_FIELD");

    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    UniValue pkg = env.body["package"];
    pkg.pushKV("download_url", "https://evil.example/runtime.exe");
    env.body.pushKV("package", pkg);
    std::string err, code;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK(code == modelnet::HCP_ERR_SOFTWARE_TRUST || code == "FORBIDDEN_FIELD");
}

BOOST_AUTO_TEST_CASE(cr11_local_05_gateway_outage)
{
    auto e = cr11_test::Lab();
    std::string code;
    UniValue ready;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, ready, code));
    BOOST_CHECK(ready["runtime_ready"].isTrue());
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
    UniValue still;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, still, code));
    BOOST_CHECK(still["runtime_ready"].isTrue());
    BOOST_CHECK(still["remote_inference"].isFalse());
    auto tok = cr11_test::Tok(*e);
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(health.status, 200);
    auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(snap.status, 200);
    BOOST_CHECK(!e->ProviderReachable());
}

BOOST_AUTO_TEST_CASE(cr11_local_06_package_substitution)
{
    auto e = cr11_test::Lab();
    const std::string other_recipe(96, '4');
    e->PutPackage(hcp_test::kCore, std::vector<unsigned char>(4, 1), other_recipe);
    auto tok = cr11_test::Tok(*e);
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", std::string("/packages/") + hcp_test::kCore, tok));
    BOOST_CHECK_EQUAL(got.status, 200);
    BOOST_CHECK_EQUAL(got.body.size(), 4u);

    std::string code, err;
    e->AcceptHandoff(
        hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code,
        err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_PACKAGE_MISMATCH);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);

    got = e->Handle(hcp_test::AuthReq(*e, "GET", std::string("/packages/") + hcp_test::kCore, tok));
    BOOST_CHECK_EQUAL(got.body.size(), 4u);
}

BOOST_AUTO_TEST_CASE(cr11_local_07_device_replay)
{
    auto e = cr11_test::Lab();
    e->PairDevice("device-b", "account-demo");
    e->SetDeviceNonce("device-b", "nonce-b");
    BOOST_CHECK(e->DevicePaired("device-b"));
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("device_id", "device-b");
    std::string err, code;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_HANDOFF_BINDING);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_local_08_physical_cancellation)
{
    auto e = cr11_test::Lab();
    e->SetDmaActive(true);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "dma-1");
    body.pushKV("maximum_exposure", "10");
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10000);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    const std::string xid = e->Cr11LastExecutionId();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 409);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), "DMA_ACTIVE");
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 10);

    e->FenceDma();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 10);
}

BOOST_AUTO_TEST_CASE(cr11_local_09_credential_isolation)
{
    auto e = cr11_test::Lab();
    e->PutSentinel("tok", "SECRET");
    e->SetPrivateKv("SECRET_KV");
    e->SetPrivatePrompt("SECRET_PROMPT");
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_logs"].isFalse());
    BOOST_CHECK(e->LogRedactionScan()["sentinels_in_export"].isFalse());
    const UniValue env = e->ChildRuntimeEnv();
    BOOST_CHECK(env["HCP_ACCESS_TOKEN"].isNull());
    BOOST_CHECK(env["AWS_SECRET_ACCESS_KEY"].isNull());
    BOOST_CHECK(env["HF_TOKEN"].isNull());
    BOOST_CHECK(env["tok_leaked"].isFalse());
    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub.write().find("SECRET") == std::string::npos);
    auto tok = cr11_test::Tok(*e);
    auto pkg = e->Handle(hcp_test::AuthReq(*e, "GET", std::string("/packages/") + hcp_test::kCore, tok));
    BOOST_CHECK(pkg.body.find("SECRET") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_local_10_coarse_reporting)
{
    auto e = cr11_test::Lab();
    e->SetReporting(false);
    e->SetPrivatePrompt("RAW_PROMPT");
    e->SetPrivateKv("RAW_KV");
    BOOST_CHECK(e->Cfg().reporting_default_off);
    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(pub["prompt"].isNull());
    BOOST_CHECK(pub["kv"].isNull());
    BOOST_CHECK(pub["local_paths"].isNull());
    BOOST_CHECK(pub.write().find("RAW_PROMPT") == std::string::npos);
    BOOST_CHECK(pub.write().find("RAW_KV") == std::string::npos);

    std::string code, err;
    const UniValue acc = e->AcceptHandoff(
        hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe), code,
        err);
    BOOST_CHECK(code.empty());
    BOOST_REQUIRE(acc.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(acc["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!acc["wallet_touched"].isTrue());
    auto tok = cr11_test::Tok(*e);
    auto ev = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok));
    BOOST_CHECK(ev.body.find("RAW_PROMPT") == std::string::npos);
    BOOST_CHECK(ev.body.find("RAW_KV") == std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
