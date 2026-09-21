// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <util/fs.h>
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_recovery_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_recovery_01)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    v.pushKV("chunk_id", "chk-never-finished");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v)).status, 404);
    auto e2 = cr12_test::Lab();
    auto tok2 = cr12_test::Tok(*e2);
    BOOST_CHECK_EQUAL(e2->Crl12PositionCount(), 0);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/institutional/imports/imp-orphan", tok2)).status, 404);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_02)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t before = e->AccountAvailable("account-demo");
    UniValue v(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    BOOST_REQUIRE_EQUAL(r.status, 200);
    const std::string id = cr12_test::Body(r)["import_id"].get_str();
    auto c = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/jobs/job-running/cancel", tok));
    BOOST_CHECK_EQUAL(c.status, 404);
    BOOST_CHECK_EQUAL(cr12_test::Body(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/imports/" + id, tok)))["status"].get_str(),
                      "VALIDATED");
    BOOST_CHECK_EQUAL(e->AccountAvailable("account-demo"), before);
    BOOST_CHECK_EQUAL(e->AccountHeld("account-demo"), 0);
    e->ExpireLease();
}

BOOST_AUTO_TEST_CASE(cr12_recovery_03)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue v(UniValue::VOBJ);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok, &v));
    const std::string id = cr12_test::Body(r)["import_id"].get_str();
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/" + id + "/commit", tok)).status, 200);
    auto c = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/jobs/job-committed/cancel", tok));
    BOOST_CHECK(c.status == 404 || cr12_test::ErrCode(c) == modelnet::HCP_ERR_JOB_COMMITTED);
    auto got = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/imports/" + id, tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["status"].get_str(), "PUBLISHED");
    BOOST_CHECK_EQUAL(cr12_test::Body(got)["generation"].get_str(), "1");
    BOOST_CHECK(cr12_test::Body(got)["custody_credit"].isFalse());
}

BOOST_AUTO_TEST_CASE(cr12_recovery_04)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("observation_id", "pos-fail");
    p.pushKV("source", "src");
    p.pushKV("generation", "1");
    p.pushKV("sequence", "1");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &p)).status, 201);
    e->CrashOutbox();
    BOOST_CHECK(!e->OutboxDrained());
    e->RecoverOutbox();
    BOOST_CHECK(e->OutboxDrained());
    e->DeliverEventDuplicates("pos-fail", 3);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/positions/pos-fail", tok)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_05)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("source", "src");
    p.pushKV("generation", "1");
    p.pushKV("sequence", "1");
    p.pushKV("mandate", "MANAGED");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &p));
    UniValue pr(UniValue::VOBJ);
    pr.pushKV("projection_id", "prj-old");
    pr.pushKV("metric_kind", "AUM");
    auto oldp = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr));
    BOOST_CHECK_EQUAL(cr12_test::Body(oldp)["status"].get_str(), "PARTIAL");
    UniValue fresh(UniValue::VOBJ);
    fresh.pushKV("status", "CURRENT");
    fresh.pushKV("value", "1");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/valuations", tok, &fresh));
    UniValue pr2(UniValue::VOBJ);
    pr2.pushKV("projection_id", "prj-new");
    pr2.pushKV("metric_kind", "AUM");
    e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &pr2));
    auto replay = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/prj-old", tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(replay)["status"].get_str(), "PARTIAL");
}

BOOST_AUTO_TEST_CASE(cr12_recovery_06)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("role", "DISCOVERY");
    a.pushKV("manifest_id", "role-hist");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &a)).status, 201);
    std::string code, err;
    BOOST_REQUIRE(e->RotateOperationalKey(2, code, err));
    BOOST_CHECK(!e->ReplayOldKeyset("op-1", code));
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/roles/role-hist", tok)).status, 200);
    UniValue n(UniValue::VOBJ);
    n.pushKV("role", "DISCOVERY");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &n)).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_07)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue plan(UniValue::VOBJ);
    plan.pushKV("objective", "own-then-run");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/capital/plans", tok, &plan));
    BOOST_REQUIRE_EQUAL(r.status, 201);
    const std::string pid = cr12_test::Body(r)["plan_id"].get_str();
    e->Crl12SetEnabled(false);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/capital/plans/" + pid, tok)).status, 200);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve", tok)).status, 200);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "GET", "/extensions/cognitive-reserve/v1.2", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/validate", tok))),
                      modelnet::HCP_ERR_PROFILE_UNSUPPORTED);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_08)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("mapping_digest", std::string(96, 'a'));
    auto r1 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &a));
    const std::string id = cr12_test::Body(r1)["export_id"].get_str();
    UniValue b(UniValue::VOBJ);
    b.pushKV("mapping_digest", std::string(96, 'b'));
    auto r2 = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &b));
    BOOST_CHECK(cr12_test::Body(r1)["mapping_digest"].get_str() != cr12_test::Body(r2)["mapping_digest"].get_str());
    auto old = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/exports/" + id, tok));
    BOOST_CHECK_EQUAL(cr12_test::Body(old)["mapping_digest"].get_str(), std::string(96, 'a'));
}

BOOST_AUTO_TEST_CASE(cr12_recovery_09)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    const int64_t cap0 = e->Cr11CapacityOf("account-demo");
    e->Crl12LoadSynthetic(32, "account-demo", "MANAGED");
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("format", "JSONL");
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &ex)).status, 201);
    for (int i = 0; i < 8; ++i) {
        BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/health", tok)).status, 200);
        BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/reserve/portfolios/port-demo/snapshot", tok)).status, 200);
    }
    BOOST_CHECK_EQUAL(e->Cr11CapacityOf("account-demo"), cap0);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_10)
{
    auto e = cr12_test::Lab();
    const std::string orig = e->Cfg().provider_id;
    e->SetPendingUnknownOn(orig, "intent-fund");
    auto sw = e->SwitchProvider("provider-read-b");
    BOOST_CHECK(sw["finance_replayed"].isFalse());
    BOOST_CHECK_EQUAL(sw["unresolved_on_old"].get_str(), "intent-fund");
    BOOST_CHECK_EQUAL(e->ExportPublic(false)["unresolved_finance_provider"].get_str(), orig);
}

BOOST_AUTO_TEST_CASE(cr12_recovery_11_persist_roundtrip)
{
    const fs::path dir = m_args.GetDataDirBase() / "cr12-hcp-persist";
    fs::create_directories(dir);
    std::string err;
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.persist_dir = dir;
    cfg.automatic_spend_atoms = 0;
    {
        auto e = modelnet::HcpEngine::Create(cfg, err);
        BOOST_REQUIRE(e);
        BOOST_REQUIRE(e->Crl12ExtensionEnabled());
        hcp_test::EnrollSelf(*e);
        auto tok = cr12_test::Tok(*e);
        UniValue role(UniValue::VOBJ);
        role.pushKV("role", "DISCOVERY");
        role.pushKV("manifest_id", "role-persist-a");
        BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &role)).status, 201);
        UniValue pos(UniValue::VOBJ);
        pos.pushKV("observation_id", "pos-persist-a");
        pos.pushKV("source", "src-persist");
        pos.pushKV("generation", "1");
        pos.pushKV("sequence", "1");
        pos.pushKV("mandate", "CUSTODY");
        BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &pos)).status, 201);
        BOOST_REQUIRE(e->Persist());
        BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 1);
    }
    auto e2 = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE(e2);
    BOOST_CHECK(e2->Crl12ExtensionEnabled());
    hcp_test::EnrollSelf(*e2);
    BOOST_CHECK_EQUAL(e2->Crl12PositionCount(), 1);
    auto tok2 = cr12_test::Tok(*e2);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/layer/roles/role-persist-a", tok2)).status, 200);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/institutional/positions/pos-persist-a", tok2)).status, 200);
}

BOOST_AUTO_TEST_SUITE_END()
