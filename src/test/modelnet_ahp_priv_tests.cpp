// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-PRIV-01  ahp_priv_01_no_required_analytics
// AHP-PRIV-02  ahp_priv_02_hardware_inventory_local
// AHP-PRIV-03  ahp_priv_03_credential_sentinels
// AHP-PRIV-04  ahp_priv_04_descriptor_host_disclosure
// AHP-PRIV-05  ahp_priv_05_no_embedded_presigned_capabilities
// AHP-PRIV-06  ahp_priv_06_multiple_directories
// AHP-PRIV-07  ahp_priv_07_gated_source
// AHP-PRIV-08  ahp_priv_08_public_versus_private_state
// AHP-PRIV     ahp_priv_prefix_visible_and_prefetch (JIT-KV-04 / JIT-PREFETCH)

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <modelnet/capability.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_acquisition.h>
#include <modelnet/package_channel.h>
#include <modelnet/package_economy.h>
#include <modelnet/package_export.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace modelnet {
void ResetCapabilityPrefetchForTests();
bool DispatchPrefetchJob(const std::string& job_id, HostResourceBroker& broker, std::string& err_code, std::string& err);
bool PutPrivatePrefix(const std::string& tenant, const UniValue& config_fingerprint, const std::string& token_prefix,
                      const UniValue& state, std::string& err_code, std::string& err);
bool GetPrivatePrefix(const std::string& requester, const std::string& owner_tenant, const UniValue& config_fingerprint,
                      const std::string& token_prefix, UniValue& state, std::string& err_code, std::string& err);
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_priv_tests, BasicTestingSetup)

namespace {

std::string HexId(char nibble) { return std::string(96, nibble); }

modelnet::LocalCapabilityGrant PrefetchGrant(uint64_t host_bytes)
{
    modelnet::LocalCapabilityGrant g;
    g.caller = "local";
    g.host_bytes = host_bytes;
    g.json = UniValue(UniValue::VOBJ);
    g.json.pushKV("automatic_spend_atoms", 0);
    return g;
}

modelnet::HostResourceBroker PrefetchBroker(uint64_t host)
{
    modelnet::HostResourceBroker b;
    modelnet::MemoryLimits lim;
    lim.host_physical_bytes = host;
    lim.host_pinned_bytes = host;
    lim.device_bytes = host;
    lim.speculative_bytes = host;
    std::string err;
    BOOST_REQUIRE(b.Configure(lim, err));
    return b;
}

UniValue KvCfg()
{
    UniValue c(UniValue::VOBJ);
    c.pushKV("adapters", "lora-a@1.0");
    c.pushKV("adapter_order", "lora-a@1.0");
    c.pushKV("tokenizer", "tok-v1");
    c.pushKV("rope", "rope-ntk");
    c.pushKV("chat_template", "chatml");
    return c;
}

UniValue CompletePrefix()
{
    UniValue s(UniValue::VOBJ);
    s.pushKV("complete_layers", 2);
    s.pushKV("expected_layers", 2);
    s.pushKV("persist_complete", true);
    s.pushKV("output_digest", std::string(96, 'b'));
    s.pushKV("saved_prefill_work", true);
    return s;
}

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

UniValue PrivModelCore()
{
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "MODEL");
    core.pushKV("label", "priv");
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
    UniValue be(UniValue::VARR);
    be.push_back("cpu");
    UniValue c(UniValue::VOBJ);
    c.pushKV("backends", be);
    v.pushKV("compatibility", c);
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

BOOST_AUTO_TEST_CASE(ahp_priv_03_credential_sentinels)
{
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("wallet_seed"));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("s3_secret_access_key"));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("private_key"));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("credential_ref"));

    UniValue portable(UniValue::VOBJ);
    portable.pushKV("schema_version", 1);
    portable.pushKV("kind", "MODEL");
    portable.pushKV("label", "public");
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::PackagePortableKeysAllowed(portable, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::LintPackagePortable(portable, err), err);

    UniValue hf = portable;
    hf.pushKV("hf_token", "HF_TEST_SENTINEL");
    BOOST_CHECK(!modelnet::PackagePortableKeysAllowed(hf, err));
    BOOST_CHECK(err.find("secret-bearing") != std::string::npos);

    UniValue s3 = portable;
    s3.pushKV("s3_secret_access_key", "S3_TEST_SENTINEL");
    BOOST_CHECK(!modelnet::PackagePortableKeysAllowed(s3, err));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("s3_secret_access_key"));

    UniValue wallet = portable;
    wallet.pushKV("wallet_seed", "WALLET_TEST_SENTINEL");
    BOOST_CHECK(!modelnet::PackagePortableKeysAllowed(wallet, err));
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("wallet_seed"));

    UniValue dist = portable;
    dist.pushKV("distribution_token", "DIST_TEST_SENTINEL");
    BOOST_CHECK(!modelnet::PackagePortableKeysAllowed(dist, err));

    UniValue nested(UniValue::VOBJ);
    nested.pushKV("diagnostics", wallet);
    BOOST_CHECK(!modelnet::LintPackagePortable(nested, err));
}

BOOST_AUTO_TEST_CASE(ahp_priv_05_no_embedded_presigned_capabilities)
{
    UniValue hint(UniValue::VOBJ);
    hint.pushKV("role", "PROVIDER");
    hint.pushKV("endpoint", "https://docs.example/btx/model-tools");
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::LintPackagePortable(hint, err), err);
    BOOST_CHECK(!modelnet::PackageContainsPresignedCapability(hint));

    UniValue presigned = hint;
    presigned.pushKV(
        "endpoint",
        "https://bucket.example/obj?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAEXAMPLE&X-Amz-Signature=deadbeef");
    BOOST_CHECK(modelnet::PackageContainsPresignedCapability(presigned));
    BOOST_CHECK(!modelnet::LintPackagePortable(presigned, err));
    BOOST_CHECK(err.find("presigned") != std::string::npos);

    UniValue keyed(UniValue::VOBJ);
    keyed.pushKV("presigned_get", "https://example/obj");
    BOOST_CHECK(modelnet::PublicExportKeyForbidden("presigned_get"));
    BOOST_CHECK(!modelnet::LintPackagePortable(keyed, err));

    UniValue notes(UniValue::VOBJ);
    notes.pushKV("path", "notes/author.md");
    notes.pushKV("text", "fetch https://bucket.example/obj?X-Amz-Signature=abc and run it");
    BOOST_CHECK(modelnet::PackageContainsPresignedCapability(notes));
    BOOST_CHECK(!modelnet::LintPackagePortable(notes, err));
}

BOOST_AUTO_TEST_CASE(ahp_priv_01_no_required_analytics)
{
    UniValue core = PrivModelCore();
    std::string err;
    BOOST_CHECK(!modelnet::PackageTelemetryForbidden(core, err));

    UniValue dirty = core;
    dirty.pushKV("telemetry_url", "https://telemetry.example/v1/collect");
    BOOST_CHECK(modelnet::PackageTelemetryForbidden(dirty, err));
    BOOST_TEST_MESSAGE("AHP-PRIV-01 remainder NOT_RUN: no packet capture");
}

BOOST_AUTO_TEST_CASE(ahp_priv_02_hardware_inventory_local)
{
    UniValue core = PrivModelCore();
    const std::string before = core.write();
    UniValue obs(UniValue::VOBJ);
    UniValue be(UniValue::VARR);
    be.push_back("cpu");
    obs.pushKV("backends", be);
    obs.pushKV("architecture", "x86_64");
    obs.pushKV("gpu_name", "INV-GPU-LOCAL-ONLY");
    obs.pushKV("cpu_model", "INV-CPU-LOCAL-ONLY");
    obs.pushKV("available_ram_bytes", "3221225472");

    std::string vid, code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::SelectPackageVariant(core, obs, vid, code, err), err);
    BOOST_CHECK_EQUAL(core.write(), before);
    BOOST_CHECK(!JsonHasKey(core, "gpu_name"));
    BOOST_CHECK(!JsonHasKey(core, "cpu_model"));
    BOOST_CHECK(!JsonHasKey(core, "available_ram_bytes"));
    BOOST_CHECK(core.write().find("INV-GPU-LOCAL-ONLY") == std::string::npos);

    const fs::path dest = m_path_root / "priv-02-native";
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("destination", dest.utf8string());
    policy.pushKV("explicit_variant", "demo-q4");
    policy.pushKV("source_policy", "NATIVE_ONLY");
    policy.pushKV("backends", be);
    policy.pushKV("gpu_name", "INV-GPU-LOCAL-ONLY");
    modelnet::AcquisitionPlan plan;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy, plan, code, err), err);
    BOOST_CHECK_EQUAL(core.write(), before);
    BOOST_CHECK(!JsonHasKey(plan.json, "gpu_name"));
    BOOST_CHECK(!JsonHasKey(plan.json, "cpu_model"));
    BOOST_CHECK(plan.json.write().find("INV-GPU-LOCAL-ONLY") == std::string::npos);
    BOOST_CHECK_EQUAL(plan.source_policy, "NATIVE_ONLY");
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_priv_04_descriptor_host_disclosure)
{
    UniValue portable(UniValue::VOBJ);
    portable.pushKV("schema_version", 1);
    portable.pushKV("kind", "MODEL");
    portable.pushKV("label", "public");
    portable.pushKV("endpoint", "https://cdn.example/descriptor.btx");
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::LintPackagePortable(portable, err), err);
    BOOST_CHECK(!portable.exists("wallet_seed"));
    BOOST_CHECK(!modelnet::PublicExportKeyForbidden("endpoint"));
    BOOST_CHECK(!modelnet::ChannelHostnameIsPublisherTrust("cdn.example"));
    BOOST_CHECK(!modelnet::ChannelHostnameIsPublisherTrust("cdn.example.com"));
}

BOOST_AUTO_TEST_CASE(ahp_priv_06_multiple_directories)
{
    const fs::path dest_a = m_path_root / "priv-dir-alpha";
    const fs::path dest_b = m_path_root / "priv-dir-beta";
    const UniValue core = PrivModelCore();
    modelnet::AcquisitionPlan plan_a, plan_b;
    std::string code, err;

    UniValue policy_a(UniValue::VOBJ);
    policy_a.pushKV("destination", dest_a.utf8string());
    policy_a.pushKV("explicit_variant", "demo-q4");
    UniValue policy_b(UniValue::VOBJ);
    policy_b.pushKV("destination", dest_b.utf8string());
    policy_b.pushKV("explicit_variant", "demo-q4");

    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy_a, plan_a, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, policy_b, plan_b, code, err), err);
    BOOST_CHECK(plan_a.destination != plan_b.destination);
    BOOST_CHECK_EQUAL(plan_a.destination, dest_a.utf8string());
    BOOST_CHECK_EQUAL(plan_b.destination, dest_b.utf8string());
    BOOST_CHECK(plan_a.json.write().find(dest_b.utf8string()) == std::string::npos);
    BOOST_CHECK(plan_b.json.write().find(dest_a.utf8string()) == std::string::npos);
    BOOST_CHECK(plan_a.plan_id_hex != plan_b.plan_id_hex);
    BOOST_CHECK(!fs::exists(dest_a));
    BOOST_CHECK(!fs::exists(dest_b));
}

BOOST_AUTO_TEST_CASE(ahp_priv_07_gated_source)
{
    const fs::path dest = m_path_root / "priv-07";
    const UniValue core = PrivModelCore();
    modelnet::AcquisitionPlan native, local;
    std::string code, err;

    UniValue p_native(UniValue::VOBJ);
    p_native.pushKV("destination", dest.utf8string());
    p_native.pushKV("explicit_variant", "demo-q4");
    p_native.pushKV("source_policy", "NATIVE_ONLY");
    UniValue p_local = p_native;
    p_local.pushKV("source_policy", "LOCAL_POLICY");

    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, p_native, native, code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxAcquisition(core, p_local, local, code, err), err);
    BOOST_CHECK_EQUAL(native.source_policy, "NATIVE_ONLY");
    BOOST_CHECK_EQUAL(local.source_policy, "LOCAL_POLICY");
    BOOST_CHECK(native.source_policy != local.source_policy);
    BOOST_CHECK(native.plan_id_hex != local.plan_id_hex);

    UniValue hf = p_native;
    hf.pushKV("source_policy", "HF");
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(core, hf, native, code, err));
    BOOST_CHECK_EQUAL(code, "NATIVE_SOURCES_UNAVAILABLE");
    BOOST_CHECK(!fs::exists(dest));
}

BOOST_AUTO_TEST_CASE(ahp_priv_08_public_versus_private_state)
{
    UniValue core = PrivModelCore();
    std::string err;
    BOOST_CHECK(!modelnet::PackageTelemetryForbidden(core, err));

    auto body_has_private = [](const std::string& body) {
        return body.find("local_paths") != std::string::npos ||
               body.find("installation_directory") != std::string::npos ||
               body.find("independent_trust_ref") != std::string::npos ||
               body.find("wallet_seed") != std::string::npos || body.find("hf_token") != std::string::npos;
    };

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/health", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.body.find("\"wallet\":false") != std::string::npos);
    BOOST_CHECK(!body_has_private(br.body));

    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/wallet", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 403);
    BOOST_CHECK(!br.ok);
    BOOST_CHECK(!body_has_private(br.body));

    const char* mutations[][2] = {
        {"/planbtxclientinstall", "{\"method\":\"planbtxclientinstall\"}"},
        {"/executebtxacquisition", "{\"method\":\"executebtxacquisition\"}"},
        {"/planbtxruntime", "{\"method\":\"planbtxruntime\"}"},
        {"/preparebountyfunding", "{\"method\":\"preparebountyfunding\"}"},
    };
    for (const auto& row : mutations) {
        BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", row[0], row[1], br));
        BOOST_CHECK_EQUAL(br.http_status, 405);
        BOOST_CHECK(!br.ok);
        BOOST_CHECK(!body_has_private(br.body));
    }

    BOOST_REQUIRE(modelnet::HandleBridgeRequest(
        "POST", "/rpc", "{\"method\":\"planbtxclientinstall\",\"params\":[]}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_CHECK(br.body.find("\"wallet\":false") != std::string::npos);
    BOOST_TEST_MESSAGE("AHP-PRIV-08 live helper unix denylist is process-tier unique_todo_priv08 + feature_modelnet_jit_capability");
}

BOOST_AUTO_TEST_CASE(ahp_priv_prefix_visible_and_prefetch)
{
    // AHP-PRIV + JIT-KV-04 / JIT-PREFETCH-01,06: scoped prefix is not a public
    // identity, and prefetch is typed intent with spend=0 (agent-recipes.md).
    using namespace modelnet;
    ResetCapabilityPrefetchForTests();

    BOOST_CHECK(PrefixVisibleToTenant("tenant-a", "tenant-a"));
    BOOST_CHECK(PrefixVisibleToTenant(" tenant-a ", "tenant-a"));
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", "tenant-b"));
    BOOST_CHECK(!PrefixVisibleToTenant("tenant-a", "tenant-a-admin"));
    BOOST_CHECK(!PrefixVisibleToTenant("public", "public"));
    BOOST_CHECK(!PrefixVisibleToTenant("PUBLIC", "PUBLIC"));
    BOOST_CHECK(!PrefixVisibleToTenant("PUBLIC_MODEL", "PUBLIC_MODEL"));
    BOOST_CHECK(!PrefixVisibleToTenant("anonymous", "anonymous"));
    BOOST_CHECK(!PrefixVisibleToTenant("ANON", "ANON"));
    BOOST_CHECK(!PrefixVisibleToTenant("ANY", "ANY"));
    BOOST_CHECK(!PrefixVisibleToTenant("LOCAL_USER", "LOCAL_USER"));
    BOOST_CHECK(!PrefixVisibleToTenant("ORGANIZATION", "ORGANIZATION"));
    BOOST_CHECK(!PrefixVisibleToTenant("RUNTIME_PROCESS", "RUNTIME_PROCESS"));
    BOOST_CHECK(!PrefixVisibleToTenant("", ""));
    BOOST_CHECK(!PrefixVisibleToTenant("*", "*"));

    std::string ec, err;
    const UniValue cfg = KvCfg();
    BOOST_REQUIRE(PutPrivatePrefix(" tenant-a ", cfg, "common-prefix", CompletePrefix(), ec, err));
    UniValue got;
    BOOST_REQUIRE(GetPrivatePrefix("tenant-a", "tenant-a", cfg, "common-prefix", got, ec, err));
    BOOST_CHECK_EQUAL(got["output_digest"].get_str(), std::string(96, 'b'));
    BOOST_CHECK(got["saved_prefill_work"].isTrue());

    UniValue other;
    BOOST_CHECK(!GetPrivatePrefix("tenant-b", "tenant-a", cfg, "common-prefix", other, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "unavailable");
    BOOST_CHECK(!other.exists("output_digest"));
    UniValue miss;
    BOOST_CHECK(!GetPrivatePrefix("tenant-b", "tenant-b", cfg, "common-prefix", miss, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "unavailable");
    BOOST_CHECK(!miss.exists("output_digest"));
    BOOST_CHECK(!GetPrivatePrefix("public", "tenant-a", cfg, "common-prefix", other, ec, err));
    BOOST_CHECK_EQUAL(ec, "PREFIX_INCOMPATIBLE");
    BOOST_CHECK(!other.exists("output_digest"));

    auto broker = PrefetchBroker(500);
    auto grant = PrefetchGrant(500);
    UniValue job;
    UniValue dirty(UniValue::VOBJ);
    dirty.pushKV("recipe_id", "secret-plan");
    dirty.pushKV("priority", "SPECULATIVE");
    dirty.pushKV("bytes", 8);
    dirty.pushKV("prompt_transcript", "user chain of thought");
    dirty.pushKV("automatic_spend_atoms", 0);
    BOOST_CHECK(!AdmitPrefetchHint(dirty, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "PRIVACY");
    BOOST_CHECK_EQUAL(job["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(broker.PrefetchJobs(), 0);

    UniValue paid(UniValue::VOBJ);
    paid.pushKV("recipe_id", "secret-plan");
    paid.pushKV("priority", "SPECULATIVE");
    paid.pushKV("bytes", 8);
    paid.pushKV("automatic_spend_atoms", 1);
    BOOST_CHECK(!AdmitPrefetchHint(paid, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(ec, "PAID_PATH_FORBIDDEN");
    BOOST_CHECK_EQUAL(job["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue spec(UniValue::VOBJ);
    spec.pushKV("recipe_id", "recipe-a");
    spec.pushKV("priority", "SPECULATIVE");
    spec.pushKV("bytes", 200);
    spec.pushKV("speculative_pool_bytes", 500);
    spec.pushKV("host_physical_bytes", 500);
    spec.pushKV("automatic_spend_atoms", 0);
    BOOST_REQUIRE(AdmitPrefetchHint(spec, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "SPECULATIVE");
    BOOST_CHECK_EQUAL(job["automatic_spend_atoms"].getInt<int>(), 0);
    const std::string spec_id = job["job_id"].get_str();

    UniValue demand(UniValue::VOBJ);
    demand.pushKV("recipe_id", "recipe-urgent");
    demand.pushKV("priority", "DEMAND");
    demand.pushKV("demand", true);
    demand.pushKV("bytes", 400);
    demand.pushKV("host_physical_bytes", 500);
    demand.pushKV("automatic_spend_atoms", 0);
    BOOST_REQUIRE(AdmitPrefetchHint(demand, grant, broker, job, ec, err));
    BOOST_CHECK_EQUAL(job["priority"].get_str(), "DEMAND");
    BOOST_CHECK(job["speculative"].isFalse());
    BOOST_CHECK_EQUAL(job["automatic_spend_atoms"].getInt<int>(), 0);
    std::string dec, derr;
    BOOST_CHECK(!DispatchPrefetchJob(spec_id, broker, dec, derr));
    BOOST_CHECK_EQUAL(dec, "HINT_EXPIRED");
}

BOOST_AUTO_TEST_SUITE_END()
