// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-CUST-01 .. 08 and HCP-INTENT-01 .. 08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_cust_intent_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_cust_01_native_key_capability)
{
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.custody_backend = modelnet::HCP_CUSTODY_EVM_GENERIC;
    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE(e);
    e->SetNativeTemplateFamily("EVM_GENERIC");
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    auto resp = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok, &body));
    BOOST_CHECK_GE(resp.status, 400);
    BOOST_CHECK(resp.body.find(modelnet::HCP_ERR_CUSTODY_UNSUPPORTED) != std::string::npos ||
                resp.body.find(modelnet::HCP_ERR_FUNDING_DISABLED) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_cust_02_frozen_script_validation)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-cust02");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    UniValue auth(UniValue::VOBJ);
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok, &auth));
    BOOST_REQUIRE_EQUAL(a.status, 200);
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("expected_body_id", env["body_id"].get_str());
    bad.pushKV("terms_id", std::string(96, 'a'));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok, &bad));
    BOOST_CHECK_GE(sub.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_cust_03_customer_lot_attribution)
{
    auto e = hcp_test::Lab(true);
    e->PutLot("lot-a", "account-demo", "out-1");
    std::string code;
    BOOST_REQUIRE(e->AttributeOutput("out-1", "account-demo", code));
    BOOST_CHECK(!e->AttributeOutput("out-1", "account-b", code));
    BOOST_CHECK_EQUAL(code, "DUPLICATE_ATTRIBUTION");
}

BOOST_AUTO_TEST_CASE(hcp_cust_04_no_synthetic_council_seats)
{
    auto e = hcp_test::Lab(true);
    e->PutAccount("sub-a", 10);
    e->PutAccount("sub-b", 10);
    auto st = e->Statements();
    BOOST_CHECK(!st["double_counted"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_cust_05_signer_timeout_ambiguity)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-cust05");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_REQUIRE_EQUAL(sub.status, 202);
    e->ForceBroadcastUnknown(iid);
    auto retry = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK(retry.body.find(modelnet::HCP_ERR_BROADCAST_UNKNOWN) != std::string::npos);
    BOOST_CHECK(retry.body.find("identical_dispatch_only") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_cust_06_recovery_drill)
{
    auto e = hcp_test::Lab(true);
    BOOST_REQUIRE(e->Persist());
    BOOST_REQUIRE(e->Restore());
    auto man = e->GoLiveManifest();
    BOOST_CHECK(!man["production_binary_replaced"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_cust_07_watch_only_export_honesty)
{
    auto e = hcp_test::Lab(true);
    auto exp = e->ExportPublic(false);
    BOOST_CHECK(!exp["self_custody"].isTrue());
    BOOST_CHECK_EQUAL(exp["custody_controller"].get_str(), "CEX_CUSTODIAL_KEY");
}

BOOST_AUTO_TEST_CASE(hcp_cust_08_signer_network_isolation)
{
    auto e = hcp_test::Lab(true);
    auto rpc = e->Handle({.method = "POST", .path = "/rpc", .body = "{}"});
    BOOST_CHECK_EQUAL(rpc.status, 404);
    BOOST_CHECK(rpc.body.find(modelnet::HCP_ERR_GENERIC_RPC) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_intent_01_idempotent_creation)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent01");
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(a.status, 201);
    BOOST_CHECK_EQUAL(b.status, 200);
    UniValue amt = body;
    UniValue amounts(UniValue::VOBJ);
    amounts.pushKV("principal_atoms", "2000");
    amounts.pushKV("network_fee_cap_atoms", "30");
    amounts.pushKV("service_fee_atoms", "20");
    amounts.pushKV("tax_atoms", "0");
    amounts.pushKV("max_total_debit_atoms", "2050");
    amt.pushKV("amounts", amounts);
    auto c = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &amt));
    BOOST_CHECK_EQUAL(c.status, 409);
}

BOOST_AUTO_TEST_CASE(hcp_intent_02_authorization_binds_intent)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent02");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    UniValue bad(UniValue::VOBJ);
    bad.pushKV("expected_body_id", std::string(96, 'f'));
    auto auth = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok, &bad));
    BOOST_CHECK_GE(auth.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_intent_03_expired_quote)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    auto q = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok));
    BOOST_REQUIRE_EQUAL(q.status, 201);
    UniValue qe;
    BOOST_REQUIRE(qe.read(q.body));
    const std::string qid = qe["body"]["quote_id"].get_str();
    e->ExpireQuote(qid);
    UniValue body(UniValue::VOBJ);
    body.pushKV("quote_id", qid);
    body.pushKV("client_operation_id", "op-intent03");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_CHECK(created.status == 400 || created.body.find(modelnet::HCP_ERR_QUOTE_EXPIRED) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_intent_04_terms_change)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent04");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    UniValue sub(UniValue::VOBJ);
    sub.pushKV("terms_id", std::string(96, 'b'));
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok, &sub));
    BOOST_CHECK_GE(r.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_intent_05_crash_before_broadcast)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent05");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_REQUIRE_EQUAL(sub.status, 202);
    const std::string tx1 = e->LastSignedTxHex();
    auto sub2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK_EQUAL(e->LastSignedTxHex(), tx1);
}

BOOST_AUTO_TEST_CASE(hcp_intent_06_crash_after_broadcast)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent06");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    e->ForceBroadcastUnknown(iid);
    auto st = e->Handle(hcp_test::AuthReq(*e, "GET", "/finance/intents/" + iid, tok));
    BOOST_CHECK(st.body.find(modelnet::HCP_ERR_BROADCAST_UNKNOWN) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_intent_07_cancel_boundary)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent07a");
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(a.body));
    auto c1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + env["body"]["intent_id"].get_str() + "/cancel", tok));
    BOOST_CHECK(c1.body.find("hold_released") != std::string::npos);
    UniValue body2(UniValue::VOBJ);
    body2.pushKV("client_operation_id", "op-intent07b");
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body2));
    UniValue env2;
    BOOST_REQUIRE(env2.read(b.body));
    const std::string iid2 = env2["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid2 + "/authorize", tok));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid2 + "/submit", tok));
    e->ForceBroadcastUnknown(iid2);
    auto c2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid2 + "/cancel", tok));
    BOOST_CHECK(c2.body.find("false_refund") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_intent_08_conversion_partial_success)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-intent08");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->CompleteConversion(iid);
    auto st = e->Handle(hcp_test::AuthReq(*e, "GET", "/finance/intents/" + iid, tok));
    BOOST_CHECK(st.body.find("conversion_complete") != std::string::npos);
    BOOST_CHECK(st.body.find("funding_failed") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
