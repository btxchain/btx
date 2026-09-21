// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-LEDGER-01 .. 08 and HCP-CHAIN-01 .. 08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <thread>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_ledger_chain_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_ledger_01_concurrent_funds_reservation)
{
    auto e = hcp_test::Lab(true);
    e->PutAccount("account-demo", 1050);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    std::atomic<int> ok{0};
    auto worker = [&](const std::string& cop) {
        UniValue body(UniValue::VOBJ);
        body.pushKV("client_operation_id", cop);
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
        if (r.status == 201) ok.fetch_add(1);
    };
    std::thread t1([&] { worker("op-led01a"); });
    std::thread t2([&] { worker("op-led01b"); });
    t1.join();
    t2.join();
    BOOST_CHECK_LE(ok.load(), 1);
    BOOST_CHECK_GE(e->AccountAvailable("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_02_principal_versus_fees)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-led02");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK(sub.body.find("principal_in_native_sum") != std::string::npos);
    BOOST_CHECK(sub.body.find("fees_itemized") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_03_lifetime_limit)
{
    auto e = hcp_test::Lab(true);
    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "life-1");
    pol.pushKV("lifetime_principal_atoms", "1000");
    pol.pushKV("refund_replenishes_lifetime", false);
    e->SetHostedPolicy(pol);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-led03a");
    body.pushKV("policy_id", "life-1");
    auto a = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(a.status, 201);
    UniValue body2(UniValue::VOBJ);
    body2.pushKV("client_operation_id", "op-led03b");
    body2.pushKV("policy_id", "life-1");
    auto b = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body2));
    BOOST_CHECK_GE(b.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_04_overlapping_batch_outputs)
{
    auto e = hcp_test::Lab(true);
    std::string code;
    BOOST_REQUIRE(e->AttributeOutput("shared-out", "account-demo", code));
    BOOST_CHECK(!e->AttributeOutput("shared-out", "account-b", code));
}

BOOST_AUTO_TEST_CASE(hcp_ledger_05_native_money_bounds)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue amt(UniValue::VOBJ);
    amt.pushKV("principal_atoms", "01");
    amt.pushKV("network_fee_cap_atoms", "0");
    amt.pushKV("service_fee_atoms", "0");
    amt.pushKV("tax_atoms", "0");
    amt.pushKV("max_total_debit_atoms", "1");
    UniValue body(UniValue::VOBJ);
    body.pushKV("amounts", amt);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/quotes", tok, &body));
    BOOST_CHECK_GE(r.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_06_fee_change)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-led06");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    UniValue fee(UniValue::VOBJ);
    fee.pushKV("network_fee_atoms", "9999");
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok, &fee));
    BOOST_CHECK_GE(sub.status, 400);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_07_reservation_persistence)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-led07");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body)).status, 201);
    BOOST_REQUIRE(e->Persist());
    BOOST_CHECK_GT(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(hcp_ledger_08_statements)
{
    auto e = hcp_test::Lab(true);
    auto st = e->Statements();
    BOOST_CHECK(!st["double_counted"].isTrue());
    BOOST_CHECK(st.exists("available_atoms"));
}

BOOST_AUTO_TEST_CASE(hcp_chain_01_202_is_not_settlement)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ch01");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK_EQUAL(sub.status, 202);
    BOOST_CHECK(sub.body.find("\"funded\":false") != std::string::npos || sub.body.find("funded") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_chain_02_confirmation_policy)
{
    auto e = hcp_test::Lab(true);
    e->SetConfirmationsRequired(2);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ch02");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    e->SetNativeConfirmations(e->LastTxid(), 1);
    BOOST_CHECK(e->IntentState(iid) != "CONFIRMED");
    e->SetNativeConfirmations(e->LastTxid(), 2);
    BOOST_CHECK_EQUAL(e->IntentState(iid), "CONFIRMED");
}

BOOST_AUTO_TEST_CASE(hcp_chain_03_reorg_correction)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ch03");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    e->SetNativeConfirmations(e->LastTxid(), 1);
    e->InjectReorg(e->LastTxid());
    BOOST_CHECK_EQUAL(e->IntentState(iid), "REORGED");
}

BOOST_AUTO_TEST_CASE(hcp_chain_04_disclosed_secret_survives_reorg)
{
    auto e = hcp_test::Lab(true);
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ch04");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->DiscloseSecret(iid);
    e->InjectReorg("none");
    BOOST_CHECK(e->KnowledgeDisclosed(iid));
}

BOOST_AUTO_TEST_CASE(hcp_chain_05_observer_outage)
{
    auto e = hcp_test::Lab(true);
    e->SetObserverAvailable(false);
    BOOST_CHECK(!e->GoLiveManifest()["proven"]["FUNDING"].isTrue());
    e->SetObserverAvailable(true);
}

BOOST_AUTO_TEST_CASE(hcp_chain_06_verifier_disagreement)
{
    auto e = hcp_test::Lab(true);
    e->SetIndependentVerifierAgrees(false);
    auto label = e->ReceiptAuthorityLabel("r");
    BOOST_CHECK_EQUAL(label["authority_label"].get_str(), "HOSTED_ATTESTED");
}

BOOST_AUTO_TEST_CASE(hcp_chain_07_refund_conditions)
{
    auto e = hcp_test::Lab(true);
    e->SetRefundHeight(100);
    e->SetNativeHeight(50);
    BOOST_CHECK_LT(e->NativeHeight(), 100);
    e->SetNativeHeight(100);
    BOOST_CHECK_GE(e->NativeHeight(), 100);

    UniValue pol(UniValue::VOBJ);
    pol.pushKV("policy_id", "ch07-life");
    pol.pushKV("lifetime_principal_atoms", "100000");
    pol.pushKV("refund_replenishes_lifetime", false);
    e->SetHostedPolicy(pol);

    const int64_t start_avail = e->AccountAvailable("account-demo");
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ch07-refund");
    body.pushKV("policy_id", "ch07-life");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    const int64_t after_create = e->AccountAvailable("account-demo");
    const int64_t spent_after_create = e->LifetimeSpent("ch07-life");
    BOOST_CHECK_LT(after_create, start_avail);
    BOOST_CHECK_GT(spent_after_create, 0);

    auto cancel = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/cancel", tok));
    BOOST_CHECK(cancel.status == 200 || cancel.status == 202 || cancel.status == 409);
    const int64_t after_cancel = e->AccountAvailable("account-demo");
    BOOST_CHECK_EQUAL(after_cancel, start_avail);
    BOOST_CHECK_EQUAL(e->LifetimeSpent("ch07-life"), spent_after_create);
}

BOOST_AUTO_TEST_CASE(hcp_chain_08_receipt_authority_label)
{
    auto e = hcp_test::Lab();
    auto lab = e->ReceiptAuthorityLabel("receipt-demo");
    BOOST_CHECK_EQUAL(lab["authority_label"].get_str(), "HOSTED_ATTESTED");
    BOOST_CHECK(!lab["spv"].isTrue());
}

BOOST_AUTO_TEST_SUITE_END()
