// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Lane C BTX-AHP-001 ACQ plan (not execute). AHP-ACQ-01..10 plan-level only.
// Live helper transfer, HF/S3, and production btxd stay NOT_RUN. Coordinator
// wires this file into test_btx later. Do not call helper, wallet, or
// production btxd.

#include <modelnet/package_acquisition.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_acq_plan_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble) { return std::string(96, nibble); }

bool JsonHasKey(const UniValue& v, const std::string& key)
{
    if (v.isObject()) {
        if (v.exists(key)) return true;
        for (const auto& k : v.getKeys()) {
            if (JsonHasKey(v[k], key)) return true;
        }
    } else if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (JsonHasKey(e, key)) return true;
        }
    }
    return false;
}

bool PlanLeaksCredentialOrExternal(const UniValue& plan_json)
{
    for (const char* k : {"hf_token", "HUGGING_FACE_HUB_TOKEN", "aws_secret_access_key",
                          "s3_secret_access_key", "wallet_seed", "wallet_passphrase",
                          "authorization_ref", "external_url", "presigned_get", "torrent",
                          "magnet", "hf_url", "s3_url", "bootstrap_url", "native_pq"}) {
        if (JsonHasKey(plan_json, k)) return true;
    }
    return false;
}

UniValue DestPolicy(const fs::path& dest)
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("destination", dest.utf8string());
    p.pushKV("explicit_variant", "demo-q4");
    return p;
}

UniValue ModelCore()
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "MODEL");
    core.pushKV("label", "acq-plan");
    UniValue r(UniValue::VOBJ);
    r.pushKV("kind", "MODEL");
    r.pushKV("id", HexId('a'));
    r.pushKV("format", "GGUF");
    UniValue resources(UniValue::VARR);
    resources.push_back(r);
    core.pushKV("resources", resources);
    UniValue v(UniValue::VOBJ);
    v.pushKV("variant_id", "demo-q4");
    v.pushKV("name", "demo-q4");
    v.pushKV("resource_id", HexId('a'));
    v.pushKV("format", "GGUF");
    UniValue vs(UniValue::VARR);
    vs.push_back(v);
    core.pushKV("variants", vs);
    UniValue acq(UniValue::VOBJ);
    acq.pushKV("default_variant", "demo-q4");
    acq.pushKV("retrieval_mode", "FREE_ONLY");
    acq.pushKV("source_policy", "NATIVE_ONLY");
    UniValue ah(UniValue::VOBJ);
    ah.pushKV("acquisition", acq);
    core.pushKV("agent_handoff", ah);
    return core;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_acq_plan_is_not_execute)
{
    const UniValue core = ModelCore();
    const fs::path dest = m_path_root / "acq-plan-must-not-create";
    BOOST_CHECK(!fs::exists(dest));

    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", dest.utf8string());
    policy.pushKV("explicit_variant", "demo-q4");

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK_EQUAL(plan.source_policy, "NATIVE_ONLY");
    BOOST_CHECK_EQUAL(plan.variant_id, "demo-q4");
    BOOST_REQUIRE_EQUAL(plan.resource_ids.size(), 1);
    BOOST_CHECK_EQUAL(plan.resource_ids[0], HexId('a'));
    BOOST_CHECK_EQUAL(plan.destination, dest.utf8string());
    BOOST_CHECK_EQUAL(plan.plan_id_hex.size(), 96);
    BOOST_CHECK_EQUAL(plan.json["retrieval_mode"].get_str(), "FREE_ONLY");
    BOOST_CHECK_EQUAL(plan.json["source_policy"].get_str(), "NATIVE_ONLY");
    BOOST_CHECK_EQUAL(plan.json["plan_id"].get_str(), plan.plan_id_hex);
    BOOST_CHECK(!plan.json.exists("authorization_ref"));
    BOOST_CHECK(!fs::exists(dest));

    modelnet::Digest48 d1, d2;
    BOOST_REQUIRE(modelnet::AcquisitionPlanDigest(plan, d1, err));
    BOOST_CHECK_EQUAL(d1.Hex(), plan.plan_id_hex);
    plan.json.pushKV("authorization_ref", "must-not-change-digest");
    BOOST_REQUIRE(modelnet::AcquisitionPlanDigest(plan, d2, err));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_acq_rejects_silent_paid_and_missing_destination)
{
    const UniValue core = ModelCore();
    std::string code, err;
    modelnet::AcquisitionPlan plan;

    UniValue paid(UniValue::VOBJ);
    paid.pushKV("destination", (m_path_root / "paid").utf8string());
    paid.pushKV("retrieval_mode", "EXPLICIT_PAID");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, paid, plan, code, err));
    BOOST_CHECK_EQUAL(code, "PAID_CONVERSION_REJECTED");
    BOOST_CHECK(!fs::exists(m_path_root / "paid"));

    UniValue convert(UniValue::VOBJ);
    convert.pushKV("destination", (m_path_root / "convert").utf8string());
    convert.pushKV("convert_to_paid", true);
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, convert, plan, code, err));
    BOOST_CHECK_EQUAL(code, "PAID_CONVERSION_REJECTED");

    UniValue wait(UniValue::VOBJ);
    wait.pushKV("destination", (m_path_root / "wait").utf8string());
    wait.pushKV("awaiting_public_release", true);
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, wait, plan, code, err));
    BOOST_CHECK_EQUAL(code, "WAITING_FOR_PUBLIC_RELEASE");
    BOOST_CHECK(!fs::exists(m_path_root / "wait"));

    UniValue nodest(UniValue::VOBJ);
    nodest.pushKV("explicit_variant", "demo-q4");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, nodest, plan, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_REQUIRED");

    UniValue remote(UniValue::VOBJ);
    remote.pushKV("destination", "https://example.invalid/weights.bin");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, remote, plan, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_REQUIRED");
}

BOOST_AUTO_TEST_CASE(ahp_acq_defaults_native_free_only)
{
    const UniValue core = ModelCore();
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", (m_path_root / "native-dest").utf8string());
    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err));
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK_EQUAL(plan.source_policy, "NATIVE_ONLY");
    BOOST_CHECK(!fs::exists(m_path_root / "native-dest"));
}

BOOST_AUTO_TEST_CASE(ahp_acq_01_no_account_native_plan)
{
    // AHP-ACQ-01 plan-level: no HF token, wallet, or chain sync is required to
    // emit a NATIVE_ONLY/FREE_ONLY plan. Live peer fetch stays NOT_RUN.
    const fs::path dest = m_path_root / "acq-01-must-not-create";
    UniValue policy = DestPolicy(dest);
    policy.pushKV("hf_token", "HF_TEST_SENTINEL");
    policy.pushKV("wallet_seed", "WALLET_TEST_SENTINEL");
    policy.pushKV("aws_secret_access_key", "S3_TEST_SENTINEL");

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK_EQUAL(plan.source_policy, "NATIVE_ONLY");
    BOOST_REQUIRE_EQUAL(plan.resource_ids.size(), 1);
    BOOST_CHECK_EQUAL(plan.resource_ids[0], HexId('a'));
    BOOST_CHECK(!PlanLeaksCredentialOrExternal(plan.json));
    BOOST_CHECK(!plan.json.exists("authorization_ref"));
    BOOST_CHECK(!fs::exists(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-01 remainder NOT_RUN: live native piece transfer is out of PlanBtxAcquisition");
}

BOOST_AUTO_TEST_CASE(ahp_acq_02_original_source_outage_does_not_rewrite_ids)
{
    // AHP-ACQ-02 plan-level: disabled HF/HTTPS/bootstrap observations must not
    // rewrite resource identity. Plan digest ignores those policy keys.
    UniValue core = ModelCore();
    UniValue hints(UniValue::VARR);
    UniValue hint(UniValue::VOBJ);
    hint.pushKV("name", "demo-q4");
    hint.pushKV("endpoint", "https://huggingface.co/outage.invalid/demo-q4");
    hints.push_back(hint);
    core.pushKV("source_hints", hints);

    const fs::path dest = m_path_root / "acq-02-must-not-create";
    UniValue policy = DestPolicy(dest);
    UniValue outage = policy;
    outage.pushKV("hf_origin_disabled", true);
    outage.pushKV("https_origin_disabled", true);
    outage.pushKV("bootstrap_provider_disabled", true);
    outage.pushKV("hf_url", "https://huggingface.co/outage.invalid");

    modelnet::AcquisitionPlan a, b;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy, a, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, outage, b, code, err), err);
    BOOST_CHECK_EQUAL(a.plan_id_hex, b.plan_id_hex);
    BOOST_CHECK_EQUAL(a.resource_ids.size(), 1);
    BOOST_CHECK_EQUAL(a.resource_ids[0], HexId('a'));
    BOOST_CHECK_EQUAL(b.resource_ids[0], HexId('a'));
    BOOST_CHECK_EQUAL(a.json["package_core_id"].get_str(), b.json["package_core_id"].get_str());
    BOOST_CHECK(!PlanLeaksCredentialOrExternal(b.json));
    BOOST_CHECK(!fs::exists(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-02 remainder NOT_RUN: remaining native providers are not exercised here");
}

BOOST_AUTO_TEST_CASE(ahp_acq_03_hint_substitution_does_not_alias_identity)
{
    // AHP-ACQ-03 plan-level: a familiar hint name/manifest must not replace the
    // committed resource id. Catalog mutation is out of this planner.
    UniValue core = ModelCore();
    UniValue hints(UniValue::VARR);
    UniValue hint(UniValue::VOBJ);
    hint.pushKV("name", "demo-q4");
    hint.pushKV("id", HexId('f'));
    hint.pushKV("manifest_id", HexId('e'));
    hint.pushKV("endpoint", "https://cdn.example.invalid/demo-q4");
    hints.push_back(hint);
    core.pushKV("source_hints", hints);

    const fs::path dest = m_path_root / "acq-03-must-not-create";
    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, DestPolicy(dest), plan, code, err), err);
    BOOST_REQUIRE_EQUAL(plan.resource_ids.size(), 1);
    BOOST_CHECK_EQUAL(plan.resource_ids[0], HexId('a'));
    BOOST_CHECK(plan.resource_ids[0] != HexId('f'));
    BOOST_CHECK_EQUAL(plan.variant_id, "demo-q4");
    BOOST_CHECK(plan.destination.find("cdn.example.invalid") == std::string::npos);
    BOOST_CHECK(!PlanLeaksCredentialOrExternal(plan.json));
    BOOST_CHECK(!fs::exists(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-03 remainder NOT_RUN: VerifiedManifest helper path is not invoked");
}

BOOST_AUTO_TEST_CASE(ahp_acq_04_native_only_rejects_external_fallback)
{
    // AHP-ACQ-04 plan-level: NATIVE_ONLY does not silently adopt HF/torrent/cloud
    // source_policy or copy those locators into the plan.
    const fs::path dest = m_path_root / "acq-04-must-not-create";
    const UniValue core = ModelCore();
    modelnet::AcquisitionPlan plan;
    std::string code, err;

    for (const char* pol : {"HF", "HTTPS", "TORRENT", "S3", "CLOUD", "EXPLICIT_EXTERNAL"}) {
        UniValue p = DestPolicy(dest);
        p.pushKV("source_policy", pol);
        BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, p, plan, code, err));
        BOOST_CHECK_EQUAL(code, "NATIVE_SOURCES_UNAVAILABLE");
        BOOST_CHECK(!fs::exists(dest));
    }

    UniValue native = DestPolicy(dest);
    native.pushKV("source_policy", "NATIVE_ONLY");
    native.pushKV("hf_url", "https://huggingface.co/working.invalid");
    native.pushKV("torrent", "magnet:?xt=urn:btx:deadbeef");
    native.pushKV("s3_url", "s3://bucket/weights.bin");
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, native, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.source_policy, "NATIVE_ONLY");
    BOOST_CHECK(!PlanLeaksCredentialOrExternal(plan.json));
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_acq_05_external_opt_in_is_distinct_plan)
{
    // AHP-ACQ-05 plan-level: LOCAL_POLICY is an explicit bounded opt-in and must
    // not claim those bytes travelled over native PQ1.
    const fs::path dest = m_path_root / "acq-05-must-not-create";
    UniValue policy = DestPolicy(dest);
    policy.pushKV("source_policy", "LOCAL_POLICY");
    policy.pushKV("maximum_download_bytes", "1048576");
    policy.pushKV("maximum_seconds", 60);

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.source_policy, "LOCAL_POLICY");
    BOOST_CHECK_EQUAL(plan.retrieval_mode, "FREE_ONLY");
    BOOST_CHECK_EQUAL(plan.json["maximum_download_bytes"].get_str(), "1048576");
    BOOST_CHECK_EQUAL(plan.json["maximum_seconds"].getInt<int64_t>(), 60);
    BOOST_CHECK(!plan.json.exists("native_pq"));
    BOOST_CHECK(!plan.json.exists("origin_mode"));
    BOOST_CHECK(!PlanLeaksCredentialOrExternal(plan.json));
    BOOST_CHECK(!fs::exists(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-05 remainder NOT_RUN: receipt transport provenance needs helper execution");
}

BOOST_AUTO_TEST_CASE(ahp_acq_06_resource_ceiling_recorded_not_bypassed)
{
    // AHP-ACQ-06 plan-level: byte/time ceilings come from local_policy, not from
    // package recommendations. Over-limit seconds fail closed.
    const fs::path dest = m_path_root / "acq-06-must-not-create";
    UniValue core = ModelCore();
    UniValue rec(UniValue::VOBJ);
    rec.pushKV("recommended_download_bytes", "999999999999");
    rec.pushKV("rare_piece", true);
    core.pushKV("acquisition_recommendation", rec);

    UniValue policy = DestPolicy(dest);
    policy.pushKV("maximum_download_bytes", "4096");
    policy.pushKV("maximum_seconds", 12);

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.json["maximum_download_bytes"].get_str(), "4096");
    BOOST_CHECK_EQUAL(plan.json["maximum_seconds"].getInt<int64_t>(), 12);
    BOOST_CHECK(plan.json["maximum_download_bytes"].get_str() != "999999999999");
    BOOST_CHECK(!fs::exists(dest));

    UniValue too_long = DestPolicy(dest);
    too_long.pushKV("maximum_seconds", 0);
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, too_long, plan, code, err));
    BOOST_CHECK_EQUAL(code, "BUDGET_EXCEEDED");

    too_long.pushKV("maximum_seconds", 604801);
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, too_long, plan, code, err));
    BOOST_CHECK_EQUAL(code, "BUDGET_EXCEEDED");
    BOOST_CHECK(!fs::exists(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-06 remainder NOT_RUN: concurrent reservation exhaustion needs helper");
}

BOOST_AUTO_TEST_CASE(ahp_acq_07_plan_is_not_filename_readiness)
{
    // AHP-ACQ-07 plan-level: a destination string or leftover file is not a
    // verified receipt. Restart of the same policy keeps the same plan id.
    const fs::path dest = m_path_root / "acq-07-stale-name.gguf";
    std::ofstream{fs::PathToString(dest)} << "not-verified-bytes";
    BOOST_REQUIRE(fs::exists(dest));

    const UniValue policy = DestPolicy(dest);
    modelnet::AcquisitionPlan a, b;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, a, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, b, code, err), err);
    BOOST_CHECK_EQUAL(a.plan_id_hex, b.plan_id_hex);
    BOOST_CHECK(!a.json.exists("state"));
    BOOST_CHECK(!a.json.exists("file_bytes_verified"));
    BOOST_CHECK(!a.json.exists("manifest_verified"));
    BOOST_CHECK(a.json["retrieval_mode"].get_str() != "MODEL_READY");
    BOOST_TEST_MESSAGE("AHP-ACQ-07 remainder NOT_RUN: piece reuse/reverify needs isolated helper cache");
}

BOOST_AUTO_TEST_CASE(ahp_acq_08_safe_materialization_plan_does_not_write)
{
    // AHP-ACQ-08 plan-level: remote destinations rejected; local dest is not
    // created; planner does not follow a swapped output symlink.
    const UniValue core = ModelCore();
    modelnet::AcquisitionPlan plan;
    std::string code, err;

    UniValue remote(UniValue::VOBJ);
    remote.pushKV("destination", "https://evil.example/weights.bin");
    remote.pushKV("explicit_variant", "demo-q4");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, remote, plan, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_REQUIRED");

    UniValue s3(UniValue::VOBJ);
    s3.pushKV("destination", "s3://bucket/out.bin");
    s3.pushKV("explicit_variant", "demo-q4");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, s3, plan, code, err));
    BOOST_CHECK_EQUAL(code, "DESTINATION_REQUIRED");

    const fs::path dest = m_path_root / "acq-08-out";
    const fs::path link = m_path_root / "acq-08-link";
    fs::create_directory(dest);
    fs::create_symlink(dest, link);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, DestPolicy(link), plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.destination, link.utf8string());
    BOOST_CHECK(fs::is_symlink(link));
    BOOST_CHECK(fs::is_empty(dest));
    BOOST_TEST_MESSAGE("AHP-ACQ-08 remainder NOT_RUN: multi-file export/hash walk needs helper materialize");
}

BOOST_AUTO_TEST_CASE(ahp_acq_09_active_output_lease_is_plan_field)
{
    // AHP-ACQ-09 plan-level: ACTIVE_LEASE is recorded. Planner does not delete
    // or replace an existing destination.
    const fs::path dest = m_path_root / "acq-09-leased";
    std::ofstream{fs::PathToString(dest)} << "leased-bytes";
    const auto before = fs::file_size(dest);

    UniValue policy = DestPolicy(dest);
    policy.pushKV("retention_policy", "ACTIVE_LEASE");

    modelnet::AcquisitionPlan plan;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.json["retention_policy"].get_str(), "ACTIVE_LEASE");
    BOOST_CHECK_EQUAL(fs::file_size(dest), before);

    UniValue garbage = DestPolicy(dest);
    garbage.pushKV("retention_policy", "DELETE_NOW");
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), garbage, plan, code, err), err);
    BOOST_CHECK_EQUAL(plan.json["retention_policy"].get_str(), "CACHE");
    BOOST_CHECK_EQUAL(fs::file_size(dest), before);
    BOOST_TEST_MESSAGE("AHP-ACQ-09 remainder NOT_RUN: GC/eviction vs runtime lease needs helper");
}

BOOST_AUTO_TEST_CASE(ahp_acq_10_idempotent_plan_rejects_conflicting_payload)
{
    // AHP-ACQ-10 plan-level: same policy → same plan_id; a material field change
    // yields a different plan. authorization_ref is not a digest input.
    const fs::path dest = m_path_root / "acq-10-must-not-create";
    UniValue policy = DestPolicy(dest);
    policy.pushKV("maximum_download_bytes", "8192");

    modelnet::AcquisitionPlan a, b, c;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, a, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), policy, b, code, err), err);
    BOOST_CHECK_EQUAL(a.plan_id_hex, b.plan_id_hex);

    modelnet::Digest48 d1, d2;
    BOOST_REQUIRE(modelnet::AcquisitionPlanDigest(a, d1, err));
    a.json.pushKV("authorization_ref", "retry-same-key");
    BOOST_REQUIRE(modelnet::AcquisitionPlanDigest(a, d2, err));
    BOOST_CHECK(d1 == d2);

    UniValue conflict = policy;
    conflict.pushKV("destination", (m_path_root / "acq-10-other").utf8string());
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(ModelCore(), conflict, c, code, err), err);
    BOOST_CHECK(a.plan_id_hex != c.plan_id_hex);
    BOOST_CHECK(!fs::exists(dest));
    BOOST_CHECK(!fs::exists(m_path_root / "acq-10-other"));
    BOOST_TEST_MESSAGE("AHP-ACQ-10 remainder NOT_RUN: caller-scoped reservation release needs helper");
}

BOOST_AUTO_TEST_SUITE_END()
