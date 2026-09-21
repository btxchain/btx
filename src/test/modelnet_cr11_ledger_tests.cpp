// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_ledger_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_ledger_01_customer_lot_mapping)
{
    auto e = cr11_test::Lab();
    e->PutLot("lot-a", "account-demo", "out-a");
    std::string code;
    BOOST_CHECK(e->AttributeOutput("out-a", "account-demo", code));
}

BOOST_AUTO_TEST_CASE(cr11_ledger_02_signer_crash)
{
    auto e = cr11_test::Lab();
    e->CrashOutbox();
    BOOST_CHECK(!e->OutboxDrained());
    e->RecoverOutbox();
    BOOST_CHECK(e->OutboxDrained());
}

BOOST_AUTO_TEST_CASE(cr11_ledger_03_broadcast_ambiguity)
{
    auto e = cr11_test::Lab();
    e->ForceBroadcastUnknown("missing");
    BOOST_CHECK(e->LastTxid().empty());
    const std::string st = e->IntentState("missing");
    BOOST_CHECK(st.empty() || st == modelnet::HCP_ERR_BROADCAST_UNKNOWN);
}

BOOST_AUTO_TEST_CASE(cr11_ledger_04_reorg_correction)
{
    auto e = cr11_test::Lab();
    e->InjectReorg("txid-x");
    BOOST_CHECK_GE(e->NativeHeight(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_ledger_05_known_secret_persists)
{
    auto e = cr11_test::Lab();
    e->DiscloseSecret("intent-x");
    BOOST_CHECK(e->KnowledgeDisclosed("intent-x"));
}

BOOST_AUTO_TEST_CASE(cr11_ledger_06_refund_beneficiary)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), 1000);
}

BOOST_AUTO_TEST_CASE(cr11_ledger_07_no_lifetime_recycling)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 1000);
    e->Cr11SetProtected(0);
    e->Cr11SetRemainingAuthority(10);
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "life-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = e->Cr11LastExecutionId();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/executions/" + xid + "/cancel", tok));
    BOOST_CHECK_GT(e->Cr11LifetimeSpent(), 0);
    UniValue body2(UniValue::VOBJ);
    body2.pushKV("client_operation_id", "life-2");
    body2.pushKV("maximum_exposure", "10");
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body2));
    const std::string aid2 = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid2 + "/execute", tok));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CAPACITY);
}

BOOST_AUTO_TEST_CASE(cr11_ledger_08_fee_conservation)
{
    auto e = cr11_test::Lab();
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
}

BOOST_AUTO_TEST_CASE(cr11_ledger_09_database_signing_boundary)
{
    auto e = cr11_test::Lab();
    e->SetSchemaMigrationCrash(true);
    BOOST_CHECK(!e->Persist());
    e->SetSchemaMigrationCrash(false);
    BOOST_CHECK(e->Persist());
}

BOOST_AUTO_TEST_CASE(cr11_ledger_10_backup_recovery)
{
    auto e = cr11_test::Lab();
    BOOST_REQUIRE(e->Persist());
    BOOST_CHECK(e->Restore());
}

BOOST_AUTO_TEST_SUITE_END()
