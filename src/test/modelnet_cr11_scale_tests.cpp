// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Unique native Cognitive Reserve v1.1 cases.

#include <test/modelnet_cr11_test.h>
#include <test/util/setup_common.h>
#include <boost/test/unit_test.hpp>

#include <set>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr11_scale_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr11_scale_01_read_load)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    const int64_t cap0 = e->Cr11CapacityOf("account-demo");
    const int64_t spent0 = e->Cr11LifetimeSpent();
    for (int i = 0; i < 64; ++i) {
        auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
        BOOST_REQUIRE_EQUAL(health.status, 200);
        BOOST_CHECK_EQUAL(cr11_test::Json(health)["automatic_spend_atoms"].getInt<int64_t>(), 0);
        BOOST_CHECK(cr11_test::Json(health)["cognitive_reserve"].isTrue());
        auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
        BOOST_REQUIRE_EQUAL(snap.status, 200);
        BOOST_CHECK_EQUAL(cr11_test::Json(snap)["body"]["allocation_capacity_atoms"].get_str(), "250");
        BOOST_CHECK(cr11_test::Json(snap)["body"]["nav_merged"].isFalse());
    }
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), cap0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), spent0);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_scale_02_write_load)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    std::set<std::string> ids;
    for (int i = 0; i < 32; ++i) {
        UniValue body(UniValue::VOBJ);
        body.pushKV("client_operation_id", "w-" + std::to_string(i));
        body.pushKV("maximum_exposure", "10");
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
        BOOST_REQUIRE_EQUAL(r.status, 201);
        const std::string id = cr11_test::Json(r)["body"]["allocation_id"].get_str();
        BOOST_CHECK(ids.insert(id).second);
        auto again = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
        BOOST_CHECK_EQUAL(again.status, 200);
        BOOST_CHECK_EQUAL(cr11_test::Json(again)["body"]["allocation_id"].get_str(), id);
        UniValue mutated(UniValue::VOBJ);
        mutated.pushKV("client_operation_id", "w-" + std::to_string(i));
        mutated.pushKV("maximum_exposure", "11");
        auto conflict = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &mutated));
        BOOST_CHECK_EQUAL(cr11_test::ErrCode(conflict), modelnet::HCP_ERR_CONFLICT);
    }
    BOOST_CHECK_EQUAL(ids.size(), 32u);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(cr11_scale_03_history_scale)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    for (int i = 0; i < 64; ++i) {
        UniValue link(UniValue::VOBJ);
        link.pushKV("link_id", "hist-" + std::to_string(i));
        auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/reserve/entities/links", tok, &link));
        BOOST_REQUIRE_EQUAL(r.status, 201);
        BOOST_CHECK_EQUAL(e->EventLogicalCount("hist-" + std::to_string(i)), 1);
    }
    auto ev = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok));
    BOOST_REQUIRE_EQUAL(ev.status, 200);
    const UniValue items = cr11_test::Json(ev)["items"];
    BOOST_REQUIRE(items.isArray());
    BOOST_CHECK_EQUAL(items.size(), 64u);
    BOOST_CHECK(cr11_test::Json(ev)["at_least_once"].isTrue());
    BOOST_CHECK(cr11_test::Json(ev)["exactly_once"].isFalse());
    auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(snap)["body"]["allocation_capacity_atoms"].get_str(), "250");
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
}

BOOST_AUTO_TEST_CASE(cr11_scale_04_queued_jobs)
{
    auto e = cr11_test::Lab();
    e->DeliverEventDuplicates("job-batch", 100);
    BOOST_CHECK_EQUAL(e->EventLogicalCount("job-batch"), 1);

    e->CrashOutbox();
    BOOST_CHECK(!e->OutboxDrained());
    auto tok = cr11_test::Tok(*e);
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "queued-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string xid = e->Cr11LastExecutionId();
    BOOST_CHECK_EQUAL(e->EventLogicalCount(xid), 0);

    e->RecoverOutbox();
    BOOST_CHECK(e->OutboxDrained());
    BOOST_CHECK_EQUAL(e->EventLogicalCount(xid), 1);
    BOOST_CHECK_EQUAL(e->EventLogicalCount("job-batch"), 1);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
}

BOOST_AUTO_TEST_CASE(cr11_scale_05_body_bound)
{
    auto e = cr11_test::Lab();
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/capital/allocations";
    req.body.assign(modelnet::HCP_MAX_BODY_BYTES + 8, 'x');
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 413);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), "BODY_TOO_LARGE");
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    BOOST_CHECK_EQUAL(e->Cr11LifetimeSpent(), 0);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);

    auto tok = cr11_test::Tok(*e);
    UniValue legs(UniValue::VARR);
    for (int i = 0; i < 33; ++i) {
        UniValue x(UniValue::VOBJ);
        x.pushKV("leg_id", "L" + std::to_string(i));
        legs.push_back(x);
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "graph-bound");
    body.pushKV("legs", legs);
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_GRAPH_LIMIT);
}

BOOST_AUTO_TEST_CASE(cr11_scale_06_failure_isolation)
{
    auto e = cr11_test::Lab();
    auto tok = cr11_test::Tok(*e);
    e->DisconnectProvider();
    BOOST_CHECK(!e->ProviderReachable());
    for (int i = 0; i < 8; ++i) {
        auto rep = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/reports", tok));
        BOOST_REQUIRE_EQUAL(rep.status, 201);
        auto prod = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/products/prod-demo", tok));
        BOOST_CHECK_EQUAL(prod.status, 200);
    }
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(health.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(health)["automatic_spend_atoms"].getInt<int64_t>(), 0);
    auto snap = e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok));
    BOOST_CHECK_EQUAL(snap.status, 200);
    BOOST_CHECK_EQUAL(cr11_test::Json(snap)["body"]["allocation_capacity_atoms"].get_str(), "250");

    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "iso-1");
    body.pushKV("maximum_exposure", "10");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations", tok, &body));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string aid = cr11_test::Json(r)["body"]["allocation_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/allocations/" + aid + "/execute", tok));
    BOOST_CHECK_EQUAL(r.status, 201);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 10);
    BOOST_CHECK(!e->ProviderReachable());
}

BOOST_AUTO_TEST_CASE(cr11_scale_07_slow_export_consumer)
{
    auto e = cr11_test::Lab();
    e->PutSentinel("tok", "SECRET-EXPORT");
    auto tok = cr11_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string id = cr11_test::Json(r)["export_id"].get_str();
    BOOST_CHECK(cr11_test::Json(r)["scoped"].isTrue());
    BOOST_CHECK(cr11_test::Json(r)["excluded_unauthorized"].isTrue());
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/exports/" + id, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(r.body.find("SECRET-EXPORT") == std::string::npos);

    r = e->Handle(hcp_test::AuthReq(*e, "POST", "/exports", tok));
    BOOST_REQUIRE_EQUAL(r.status, 202);
    BOOST_CHECK(cr11_test::Json(r)["include_secrets"].isFalse());
    BOOST_CHECK(cr11_test::Json(r)["ready"].isFalse());
    const std::string hid = cr11_test::Json(r)["export_id"].get_str();
    r = e->Handle(hcp_test::AuthReq(*e, "GET", "/exports/" + hid, tok));
    BOOST_CHECK_EQUAL(r.status, 200);
    BOOST_CHECK(cr11_test::Json(r)["ready"].isFalse());
    BOOST_CHECK(cr11_test::Json(r)["retrieved"].isTrue());
    BOOST_CHECK(r.body.find("SECRET-EXPORT") == std::string::npos);

    const UniValue pub = e->ExportPublic(false);
    BOOST_CHECK(!pub.exists("access_token"));
    BOOST_CHECK(pub.write().find("SECRET-EXPORT") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(cr11_scale_08_leader_crash)
{
    auto e = cr11_test::Lab();
    e->PutAccount("account-demo", 100000);
    auto tok = cr11_test::Tok(*e);

    UniValue amounts(UniValue::VOBJ);
    amounts.pushKV("principal_atoms", "10");
    amounts.pushKV("network_fee_cap_atoms", "0");
    amounts.pushKV("service_fee_atoms", "0");
    amounts.pushKV("tax_atoms", "0");
    amounts.pushKV("max_total_debit_atoms", "10");

    UniValue first(UniValue::VOBJ);
    first.pushKV("client_operation_id", "leader-alive");
    first.pushKV("amounts", amounts);
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &first));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    const std::string live_id = cr11_test::Json(created)["body"]["intent_id"].get_str();

    e->ExpireLease();
    e->SetExecutorOwner("replica-2");
    BOOST_CHECK_EQUAL(e->DualInstancePeerNote()["instance_id"].get_str(), e->Cfg().instance_id);
    BOOST_CHECK(e->DualInstancePeerNote()["independent"].isTrue());

    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + live_id + "/authorize", tok));
    auto sub_live = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + live_id + "/submit", tok));
    const std::string tx_after_crash = e->LastTxid();

    UniValue orphan(UniValue::VOBJ);
    orphan.pushKV("client_operation_id", "leader-elect");
    orphan.pushKV("amounts", amounts);
    created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &orphan));
    BOOST_REQUIRE_EQUAL(created.status, 201);
    const std::string elect_id = cr11_test::Json(created)["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + elect_id + "/authorize", tok));
    auto sub_elect = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + elect_id + "/submit", tok));
    BOOST_CHECK_EQUAL(sub_elect.status, 409);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(sub_elect), modelnet::HCP_ERR_FENCED);
    BOOST_CHECK_EQUAL(e->LastTxid(), tx_after_crash);
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    (void)sub_live;
}

BOOST_AUTO_TEST_CASE(cr11_scale_09_cursor_expiry)
{
    auto e = cr11_test::Lab();
    e->RestoreCatalogueIndex();
    auto tok = cr11_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "GET", "/events", tok);
    req.query = "cursor=1";
    auto r = e->Handle(req);
    BOOST_CHECK_EQUAL(r.status, 409);
    BOOST_CHECK_EQUAL(cr11_test::ErrCode(r), modelnet::HCP_ERR_CURSOR_TOO_OLD);

    auto fresh = e->Handle(hcp_test::AuthReq(*e, "GET", "/events", tok));
    BOOST_CHECK_EQUAL(fresh.status, 200);
    BOOST_CHECK(cr11_test::Json(fresh)["items"].isArray());
}

BOOST_AUTO_TEST_CASE(cr11_scale_10_evidence_truth)
{
    auto e = cr11_test::Lab();
    UniValue man = e->GoLiveManifest();
    BOOST_CHECK_EQUAL(man["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(!man["production_binary_replaced"].isTrue());
    BOOST_CHECK(man["proven"]["DISCOVERY"].isTrue());
    BOOST_CHECK(man.exists("claimed_profiles"));
    BOOST_CHECK(man.exists("proven"));
    BOOST_CHECK(man.exists("not_run"));
    e->SetObserverAvailable(false);
    man = e->GoLiveManifest();
    BOOST_CHECK(!man["proven"]["FUNDING"].isTrue());
    BOOST_REQUIRE(man["not_run"].isArray());
    BOOST_CHECK_GE(man["not_run"].size(), 1u);
    BOOST_CHECK_EQUAL(man["not_run"][0].get_str(), "FUNDING_NATIVE_SIGNER");
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, modelnet::HCP_AUTOMATIC_SPEND_ATOMS);
    BOOST_CHECK_EQUAL(modelnet::HCP_AUTOMATIC_SPEND_ATOMS, 0);
    auto tok = cr11_test::Tok(*e);
    auto health = e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok));
    BOOST_CHECK_EQUAL(cr11_test::Json(health)["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(cr11_test::Json(health)["simulation_only"].isTrue(), e->Cfg().simulation_only);
}

BOOST_AUTO_TEST_SUITE_END()
