// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// Exclusive CRL/1.2 gap-fill locks. Not in CMake; coordinator registers if needed.
// Several cases FAIL until hcp_engine.cpp / hcp_types.h patches land.

#include <test/modelnet_cr12_test.h>
#include <test/util/setup_common.h>
#include <crypto/sha384.h>
#include <span.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>
#include <vector>

namespace {

std::unique_ptr<modelnet::HcpEngine> PersistLab(const fs::path& dir)
{
    auto cfg = modelnet::HcpFundingLabPreset();
    cfg.persist_dir = dir;
    cfg.automatic_spend_atoms = 0;
    std::string err;
    auto e = modelnet::HcpEngine::Create(cfg, err);
    BOOST_REQUIRE_MESSAGE(e, err);
    hcp_test::EnrollSelf(*e);
    e->PairDevice("device-demo", "account-demo");
    e->SetDeviceNonce("device-demo", "demo-nonce-not-production");
    e->SetLocalGrant(hcp_test::OwnerGrant());
    e->PutAccount("account-demo", 1000);
    return e;
}

std::string Sha384Of(const std::string& bytes)
{
    unsigned char d[CSHA384::OUTPUT_SIZE];
    CSHA384 h;
    h.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, sizeof(d)});
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(modelnet_cr12_gapfill_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(cr12_gap_persist_reopen_maps)
{
    const fs::path dir = m_args.GetDataDirBase() / "crl12-persist";
    fs::create_directories(dir);
    auto e = PersistLab(dir);
    auto tok = cr12_test::Tok(*e);
    UniValue ast(UniValue::VOBJ);
    ast.pushKV("asset_id", "ast-persist");
    ast.pushKV("namespace", "lab");
    ast.pushKV("value", "persist-1");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/assets", tok, &ast)).status, 201);
    UniValue row(UniValue::VOBJ);
    row.pushKV("observation_id", "pos-persist");
    row.pushKV("source", "src-p");
    row.pushKV("generation", "1");
    row.pushKV("sequence", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &row)).status, 201);
    UniValue role(UniValue::VOBJ);
    role.pushKV("role", "DISCOVERY");
    role.pushKV("manifest_id", "role-persist");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &role)).status, 201);
    BOOST_REQUIRE(e->Persist());
    BOOST_CHECK_EQUAL(e->Crl12PositionCount(), 1);
    e.reset();

    auto e2 = PersistLab(dir);
    auto tok2 = cr12_test::Tok(*e2);
    BOOST_CHECK_EQUAL(e2->Crl12PositionCount(), 1);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/institutional/positions/pos-persist", tok2)).status, 200);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/institutional/assets/ast-persist", tok2)).status, 200);
    BOOST_CHECK_EQUAL(e2->Handle(hcp_test::AuthReq(*e2, "GET", "/layer/roles/role-persist", tok2)).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_gap_get_positions_as_of_required)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue row(UniValue::VOBJ);
    row.pushKV("observation_id", "pos-asof");
    row.pushKV("source", "src-a");
    row.pushKV("generation", "1");
    row.pushKV("sequence", "0");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &row)).status, 201);
    auto missing = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok));
    BOOST_CHECK_NE(missing.status, 200);
    BOOST_CHECK(missing.status == 400 || missing.status == 422);
    auto ok = hcp_test::AuthReq(*e, "GET", "/institutional/positions", tok);
    ok.query = "as_of=" + std::to_string(e->Now()) + "&observed_cutoff=" + std::to_string(e->Now());
    BOOST_CHECK_EQUAL(e->Handle(ok).status, 200);
}

BOOST_AUTO_TEST_CASE(cr12_gap_projection_create_returns_job)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("return_job", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_CHECK(r.status == 202 || r.status == 201);
    BOOST_CHECK_EQUAL(cr12_test::ObjType(r), modelnet::HCP_TYPE_LAYER_JOB);
    BOOST_CHECK(cr12_test::Body(r).exists("job_id"));
    BOOST_CHECK(cr12_test::Body(r).exists("result_ref"));
    const std::string jid = cr12_test::Body(r)["job_id"].get_str();
    auto job = e->Handle(hcp_test::AuthReq(*e, "GET", "/layer/jobs/" + jid, tok));
    BOOST_CHECK_EQUAL(job.status, 200);
    if (cr12_test::Body(job)["status"].get_str() != "SUCCEEDED") {
        const std::string pid = cr12_test::Body(r)["result_ref"].get_str();
        BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/projections/" + pid, tok))),
                          "JOB_PENDING");
    }
}

BOOST_AUTO_TEST_CASE(cr12_gap_binding_revoked_blocks_new_record)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue b(UniValue::VOBJ);
    b.pushKV("role", "ASSET_SERVICING");
    b.pushKV("binding_id", "bind-revoke-gap");
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &b)).status, 201);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings/bind-revoke-gap/revoke", tok)).status, 200);
    UniValue row(UniValue::VOBJ);
    row.pushKV("observation_id", "pos-after-revoke");
    row.pushKV("source", "src-a");
    row.pushKV("generation", "1");
    row.pushKV("sequence", "0");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &row))),
                      "BINDING_REVOKED");
}

BOOST_AUTO_TEST_CASE(cr12_gap_inbound_signed_observation_mldsa)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpEnvelope env;
    env.object_type = modelnet::HCP_TYPE_POSITION_OBS;
    env.body.pushKV("schema_revision", "1.2");
    env.body.pushKV("observation_id", "pos-signed");
    env.body.pushKV("source", "src-signed");
    env.body.pushKV("generation", "1");
    env.body.pushKV("sequence", "0");
    env.body.pushKV("quantity", "1");
    env.body.pushKV("status", "OPEN");
    std::string err;
    BOOST_REQUIRE(e->SignAsProvider(env, err));
    BOOST_REQUIRE(modelnet::HcpVerify(env, e->OpPk(), err));
    const UniValue wire = modelnet::EncodeHcpEnvelope(env);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &wire)).status, 201);
    BOOST_CHECK_EQUAL(e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/positions/pos-signed", tok)).status, 200);
    env.body.pushKV("tampered", true);
    const UniValue bad = modelnet::EncodeHcpEnvelope(env);
    auto rbad = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &bad));
    BOOST_CHECK_NE(rbad.status, 201);
    BOOST_CHECK(cr12_test::ErrCode(rbad) == "SIGNATURE_INVALID" || cr12_test::ErrCode(rbad) == modelnet::HCP_ERR_BODY_ID_MISMATCH);
}

BOOST_AUTO_TEST_CASE(cr12_gap_package_type_names)
{
    BOOST_CHECK(modelnet::HcpObjectTypeOk("AdapterCapabilityManifestV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("InstitutionalAssetRecordV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("RightsStatementV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("InteroperabilityReceiptV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("ScenarioDefinitionV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("ScenarioResultV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("ConformanceStatementV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("InstitutionalAssetV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("AssetRightsV1_2"));
    BOOST_CHECK(modelnet::HcpObjectTypeOk("ImportManifestV1_2"));
}

BOOST_AUTO_TEST_CASE(cr12_gap_stage_declared_chunk_digest)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpHttpRequest req = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok);
    req.body = "hello-chunk";
    req.query = "digest=" + std::string(96, '0') + "&length=4";
    auto r = e->Handle(req);
    BOOST_CHECK_NE(r.status, 201);
    BOOST_CHECK(cr12_test::ErrCode(r) == "CHUNK_MISMATCH" || cr12_test::ErrCode(r) == modelnet::HCP_ERR_CHUNK_DIGEST);
}

BOOST_AUTO_TEST_CASE(cr12_gap_export_chunk_digest_roundtrip)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue csv(UniValue::VOBJ);
    csv.pushKV("format", "CSV");
    auto man = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/exports", tok, &csv));
    BOOST_REQUIRE_EQUAL(man.status, 201);
    BOOST_REQUIRE(cr12_test::Body(man)["chunks"].isArray());
    BOOST_REQUIRE(cr12_test::Body(man)["chunks"].size() >= 1);
    const std::string eid = cr12_test::Body(man)["export_id"].get_str();
    const std::string cid = cr12_test::Body(man)["chunks"][0]["chunk_id"].get_str();
    const std::string digest = cr12_test::Body(man)["chunks"][0]["digest"].get_str();
    auto bytes = e->Handle(hcp_test::AuthReq(*e, "GET", "/institutional/exports/" + eid + "/chunks/" + cid, tok));
    BOOST_CHECK_EQUAL(bytes.status, 200);
    BOOST_CHECK_EQUAL(Sha384Of(bytes.body), digest);
}

BOOST_AUTO_TEST_CASE(cr12_gap_spec_error_codes_exist)
{
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_PROFILE_UNSUPPORTED), "PROFILE_UNSUPPORTED");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_ROLE_UNAVAILABLE), "ROLE_UNAVAILABLE");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_ROLE_EFFECT), "ROLE_EFFECT_MISMATCH");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_IDENTIFIER_COLLISION), "IDENTIFIER_COLLISION");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_OBSERVATION_CONFLICT), "OBSERVATION_CONFLICT");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_CONFLICT), "IDEMPOTENCY_CONFLICT");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_MAPPING_CAS), "MAPPING_CAS");
    BOOST_CHECK_EQUAL(std::string(modelnet::HCP_ERR_CHUNK_DIGEST), "CHUNK_DIGEST");
}

BOOST_AUTO_TEST_CASE(cr12_gap_idempotency_key_header)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue discovery(UniValue::VOBJ);
    discovery.pushKV("role", "DISCOVERY");
    auto first = hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &discovery);
    first.headers["idempotency-key"] = "ik-1";
    BOOST_CHECK_EQUAL(e->Handle(first).status, 201);

    UniValue custody(UniValue::VOBJ);
    custody.pushKV("role", "CUSTODY");
    auto conflict = hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &custody);
    conflict.headers["idempotency-key"] = "ik-1";
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(conflict)), modelnet::HCP_ERR_CONFLICT);

    auto replay = hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &discovery);
    replay.headers["idempotency-key"] = "ik-1";
    BOOST_CHECK_EQUAL(e->Handle(replay).status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_gap_role_sequence_rollback)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue ahead(UniValue::VOBJ);
    ahead.pushKV("role", "DISCOVERY");
    ahead.pushKV("manifest_id", "role-seq-rollback");
    ahead.pushKV("sequence", 2);
    BOOST_REQUIRE_EQUAL(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &ahead)).status, 201);
    UniValue behind(UniValue::VOBJ);
    behind.pushKV("role", "DISCOVERY");
    behind.pushKV("manifest_id", "role-seq-rollback");
    behind.pushKV("sequence", 1);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/roles", tok, &behind));
    BOOST_CHECK_NE(r.status, 201);
    BOOST_CHECK_EQUAL(r.status, 409);
}

BOOST_AUTO_TEST_CASE(cr12_gap_network_mismatch)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue b(UniValue::VOBJ);
    b.pushKV("role", "ASSET_SERVICING");
    b.pushKV("network", "mainnet");
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/layer/bindings", tok, &b))),
                      modelnet::HCP_ERR_NETWORK_MISMATCH);
}

BOOST_AUTO_TEST_CASE(cr12_gap_source_not_authorized)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue row(UniValue::VOBJ);
    row.pushKV("observation_id", "pos-unauth-src");
    row.pushKV("source", "src-a");
    row.pushKV("generation", "1");
    row.pushKV("sequence", "0");
    row.pushKV("source_not_authorized", true);
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/positions/batches", tok, &row))),
                      modelnet::HCP_ERR_SOURCE_NOT_AUTHORIZED);
}

BOOST_AUTO_TEST_CASE(cr12_gap_import_not_validated)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/imports/imp-never-validated/commit", tok));
    BOOST_CHECK_EQUAL(cr12_test::ErrCode(r), modelnet::HCP_ERR_IMPORT_NOT_VALIDATED);
}

BOOST_AUTO_TEST_CASE(cr12_gap_instruction_draft_only)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue a(UniValue::VOBJ);
    a.pushKV("requested_action", "DRAFT_RESERVE_ALLOCATION");
    a.pushKV("execute", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/instructions", tok, &a));
    const std::string code = cr12_test::ErrCode(r);
    BOOST_CHECK(code == modelnet::HCP_ERR_INSTRUCTION_NOT_EXECUTE || code == modelnet::HCP_ERR_DRAFT_ONLY);
    BOOST_CHECK_NE(r.status, 201);
}

BOOST_AUTO_TEST_CASE(cr12_gap_scenario_shocks)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue s(UniValue::VOBJ);
    s.pushKV("kind", "RESERVE_PRICE");
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/scenarios", tok, &s));
    BOOST_CHECK(r.status == 201 || r.status == 202);
    BOOST_CHECK(cr12_test::Body(r).exists("financial_change"));
    BOOST_CHECK(cr12_test::Body(r).exists("operational_impacts"));
    BOOST_CHECK(cr12_test::Body(r).exists("distinct_methodology"));
    BOOST_CHECK(cr12_test::Body(r)["distinct_methodology"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_gap_source_unavailable)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("source_unavailable", true);
    auto r = e->Handle(hcp_test::AuthReq(*e, "POST", "/institutional/projections", tok, &p));
    BOOST_REQUIRE(r.status == 201 || r.status == 202);
    BOOST_REQUIRE(cr12_test::Body(r)["metric_results"].isArray());
    BOOST_REQUIRE(cr12_test::Body(r)["metric_results"].size() >= 1);
    const UniValue metric = cr12_test::Body(r)["metric_results"][0];
    BOOST_CHECK(metric["complete"].isFalse());
    BOOST_CHECK(metric["value"].isNull());
    BOOST_CHECK(metric["no_grand_total"].isTrue());
}

BOOST_AUTO_TEST_CASE(cr12_gap_chunk_16mib_cap)
{
    auto e = cr12_test::Lab();
    auto tok = cr12_test::Tok(*e);
    modelnet::HcpHttpRequest ok = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok);
    ok.body = std::string(2 * 1024 * 1024, 'a');
    BOOST_CHECK_EQUAL(e->Handle(ok).status, 201);
    modelnet::HcpHttpRequest too = hcp_test::AuthReq(*e, "POST", "/institutional/imports/chunks", tok);
    too.body = std::string(16 * 1024 * 1024 + 1, 'a');
    BOOST_CHECK_EQUAL(e->Handle(too).status, 413);
}

BOOST_AUTO_TEST_CASE(cr12_gap_tenant_get_job)
{
    auto a = cr12_test::Lab();
    auto b = cr12_test::Lab();
    auto tok_a = cr12_test::Tok(*a);
    auto tok_b = cr12_test::Tok(*b);

    UniValue ast(UniValue::VOBJ);
    ast.pushKV("asset_id", "ast-tenant-a");
    ast.pushKV("namespace", "lab");
    ast.pushKV("value", "tenant-a-only");
    BOOST_REQUIRE_EQUAL(a->Handle(hcp_test::AuthReq(*a, "POST", "/institutional/assets", tok_a, &ast)).status, 201);

    UniValue p(UniValue::VOBJ);
    p.pushKV("metric_kind", "AUM");
    p.pushKV("return_job", true);
    auto jr = a->Handle(hcp_test::AuthReq(*a, "POST", "/institutional/projections", tok_a, &p));
    BOOST_REQUIRE(jr.status == 202 || jr.status == 201);
    BOOST_REQUIRE(cr12_test::Body(jr).exists("job_id"));
    const std::string jid = cr12_test::Body(jr)["job_id"].get_str();
    BOOST_CHECK_EQUAL(a->Handle(hcp_test::AuthReq(*a, "GET", "/layer/jobs/" + jid, tok_a)).status, 200);
    BOOST_CHECK_NE(b->Handle(hcp_test::AuthReq(*b, "GET", "/layer/jobs/" + jid, tok_b)).status, 200);

    auto list_b = b->Handle(hcp_test::AuthReq(*b, "GET", "/institutional/assets", tok_b));
    BOOST_CHECK_EQUAL(list_b.status, 200);
    BOOST_CHECK(list_b.body.find("ast-tenant-a") == std::string::npos);
    BOOST_CHECK(list_b.body.find("tenant-a-only") == std::string::npos);

    auto analytics = cr12_test::Tok(*a, cr12_test::AnalyticsScopes());
    BOOST_CHECK_EQUAL(a->Handle(hcp_test::AuthReq(*a, "GET", "/institutional/assets", analytics)).status, 200);
    BOOST_CHECK_EQUAL(a->Handle(hcp_test::AuthReq(*a, "GET", "/institutional/assets/ast-tenant-a", analytics)).status, 200);
}

BOOST_AUTO_TEST_SUITE_END()
