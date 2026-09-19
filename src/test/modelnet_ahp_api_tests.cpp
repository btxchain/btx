// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-API-01..08 helper RPC aliases. Frame/core/signature/trust stay separate.

#include <modelnet/catalog.h>
#include <modelnet/hello_caps.h>
#include <modelnet/helper.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_acquisition.h>
#include <modelnet/package_core.h>
#include <test/util/setup_common.h>
#include <test/modelnet_n02_idem.h>
#include <univalue.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_api_tests, BasicTestingSetup)

namespace {

UniValue Rpc(const std::string& method, const UniValue& o)
{
    UniValue inner = WithN02Idempotency(method, o);
    UniValue params(UniValue::VARR);
    params.push_back(inner);
    UniValue req(UniValue::VOBJ);
    req.pushKV("method", method);
    req.pushKV("params", params);
    return req;
}

fs::path Fixture(const char* name)
{
#ifdef MODELNET_AHP_FIXTURE_DIR
    return fs::PathFromString(MODELNET_AHP_FIXTURE_DIR) / fs::PathFromString(name);
#else
    return fs::PathFromString(std::string{__FILE__}).parent_path() / "data" / "agent-package" /
           fs::PathFromString(name);
#endif
}

const char* kCoreId =
    "73e72380ef4959614ec34e0796a12d59bf4abf483c044b55b66c167d6bb6670db8ec3dd7d26d0e455a072288606e7b58";

std::vector<unsigned char> ReadBytes(const fs::path& p)
{
    std::ifstream in{p, std::ios::binary};
    BOOST_REQUIRE(in);
    const std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return {raw.begin(), raw.end()};
}

std::string HelperErr(bool ok, const UniValue& result, const std::string& code)
{
    if (!ok) return code;
    if (result.exists("error_code") && result["error_code"].isStr()) return result["error_code"].get_str();
    return {};
}

#ifdef MODELNET_BTX_OPEN_PATH
std::string ShellQuote(const std::string& s)
{
    std::string q = "'";
    for (char c : s) {
        if (c == '\'') q += "'\\''";
        else q += c;
    }
    q += "'";
    return q;
}
#endif

} // namespace

BOOST_AUTO_TEST_CASE(ahp_api_01_capabilities)
{
    const fs::path tmp = m_path_root / "ahp-api-cap";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxpackagecapabilities", UniValue(UniValue::VOBJ)), result, code, err));
    BOOST_CHECK(result["BTXPKG_CORE_V2"].get_bool());
    BOOST_CHECK(result["AGENT_HANDOFF_V1"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result["wallet_sign"].get_bool());
    BOOST_CHECK(!result["writes_project_agents_md"].get_bool());
    BOOST_CHECK(!result["remote_inference"].get_bool());

    const UniValue advertised = modelnet::HelloCapabilityArray();
    BOOST_REQUIRE(advertised.isArray());
    bool saw_handoff = false, saw_core_v2 = false, saw_pkg = false;
    for (const auto& c : advertised.getValues()) {
        std::string n;
        BOOST_REQUIRE(modelnet::HelloCapabilityEntryName(c, n));
        BOOST_CHECK(c.isObject());
        BOOST_CHECK(c.exists("min") && c.exists("max"));
        if (n == "AGENT_HANDOFF_V1") saw_handoff = true;
        if (n == "BTXPKG_CORE_V2") saw_core_v2 = true;
        if (n == "PACKAGE_V1") saw_pkg = true;
    }
    BOOST_CHECK(saw_handoff);
    BOOST_CHECK(saw_core_v2);
    BOOST_CHECK(saw_pkg);

    UniValue hello(UniValue::VOBJ);
    hello.pushKV("capabilities", advertised);
    BOOST_CHECK(modelnet::HelloHasCapability(hello, "AGENT_HANDOFF_V1"));
    UniValue str_caps(UniValue::VARR);
    str_caps.push_back("AGENT_HANDOFF_V1");
    UniValue hello_str(UniValue::VOBJ);
    hello_str.pushKV("capabilities", str_caps);
    BOOST_CHECK(modelnet::HelloHasCapability(hello_str, "AGENT_HANDOFF_V1"));

    std::string alias_of;
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("inspectbtxpackage", alias_of), "inspectbtxpackage");
    BOOST_CHECK(alias_of.empty());
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("exportbtxpackage", alias_of), "exportbtxbundle");
    BOOST_CHECK_EQUAL(alias_of, "exportbtxbundle");
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("planbtxacquisition", alias_of), "planbtxacquisition");
    BOOST_CHECK(alias_of.empty());
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("getbtxpackagecapabilities", alias_of),
                      "getbtxpackagecapabilities");
    BOOST_CHECK(alias_of.empty());
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("getmodelcapabilities", alias_of), "getmodelnetworkinfo");
    BOOST_CHECK_EQUAL(alias_of, "getmodelnetworkinfo");
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("inspectmodelstorage", alias_of), "testcloudstorage");
    const std::string first_target = alias_of;
    BOOST_CHECK_EQUAL(modelnet::ResolveHelperMethodAlias("testmodelstorage", alias_of), first_target);
    BOOST_CHECK_EQUAL(alias_of, "testcloudstorage");
}

BOOST_AUTO_TEST_CASE(ahp_api_02_inspect_fields_never_collapsed)
{
    const fs::path tmp = m_path_root / "ahp-api-insp";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("path", fs::PathToString(Fixture("model-agent.btx")));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("inspectbtxpackage", arg), result, code, err), err);
    BOOST_CHECK(result["ok"].get_bool());
    BOOST_CHECK_EQUAL(result["frame_integrity"].get_str(), "PASS");
    BOOST_CHECK_EQUAL(result["core_id"].get_str(), kCoreId);
    BOOST_CHECK_EQUAL(result["signature_status"].get_str(), "UNSIGNED");
    BOOST_CHECK_EQUAL(result["publisher_trust"].get_str(), "NOT_EVALUATED");
    BOOST_CHECK(!result["model_bytes_verified"].get_bool());
    BOOST_CHECK(!result["executed_runtime"].get_bool());
    BOOST_CHECK(!result["installed_software"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(result["core_valid"].get_bool());
}

BOOST_AUTO_TEST_CASE(ahp_api_03_get_document_inert)
{
    const fs::path tmp = m_path_root / "ahp-api-doc";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("path", fs::PathToString(Fixture("model-agent.btx")));
    arg.pushKV("document", "AGENTS.md");
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxpackagedocument", arg), result, code, err), err);
    BOOST_CHECK(result["untrusted_scoped_data"].get_bool());
    BOOST_CHECK(!result["workspace_written"].get_bool());
    BOOST_CHECK(!result["project_agents_md"].get_bool());
    BOOST_CHECK_EQUAL(result["path"].get_str(), "AGENTS.md");
    BOOST_CHECK(result["text"].get_str().find("Package purpose") != std::string::npos);
    BOOST_CHECK(!fs::exists(m_path_root / "AGENTS.md"));

    modelnet::BrowserBridgeResponse br;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/planbtxclientinstall",
                                                "{\"method\":\"planbtxclientinstall\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/executebtxacquisition",
                                                "{\"method\":\"executebtxacquisition\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/planbtxruntime", "{\"method\":\"planbtxruntime\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/rpc", "{\"method\":\"preparebountyfunding\"}", br));
    BOOST_CHECK_EQUAL(br.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("GET", "/health", "", br));
    BOOST_CHECK_EQUAL(br.http_status, 200);
    BOOST_CHECK(br.body.find("\"wallet\":false") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(ahp_api_04_plan_execute_cancel_acquisition)
{
    const fs::path tmp = m_path_root / "ahp-api-acq";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("path", fs::PathToString(Fixture("model-agent.btx")));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", arg), result, code, err), err);
    BOOST_CHECK_EQUAL(result["retrieval_mode"].get_str(), "FREE_ONLY");
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    const std::string plan_id = result["plan_id"].get_str();
    UniValue ex(UniValue::VOBJ);
    ex.pushKV("plan_id", plan_id);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("executebtxacquisition", ex), result, code, err), err);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(!result["runtime_executed"].get_bool());
    BOOST_CHECK_EQUAL(result["state"].get_str(), "SELECTION_READY");
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("getbtxacquisition", ex), result, code, err));
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("cancelbtxacquisition", ex), result, code, err));
    BOOST_CHECK(result["cancelled"].get_bool());

    UniValue insp(UniValue::VOBJ);
    insp.pushKV("path", fs::PathToString(Fixture("model-agent.btx")));
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("inspectbtxpackage", insp), result, code, err));
    BOOST_CHECK(!result["installed_software"].get_bool());
    BOOST_CHECK(!result["executed_runtime"].get_bool());
    BOOST_CHECK_EQUAL(result["signature_status"].get_str(), "UNSIGNED");

    // AHP-API-04: spawn btx-open on the unsigned fixture. Inspect only;
    // automatic_spend_atoms stays 0; do not write workspace AGENTS.md.
#ifdef MODELNET_BTX_OPEN_PATH
    BOOST_TEST_MESSAGE(std::string("AHP-API-04 btx-open binary: ") + MODELNET_BTX_OPEN_PATH);
    BOOST_REQUIRE(fs::exists(fs::PathFromString(MODELNET_BTX_OPEN_PATH)));
    const std::string fixture = fs::PathToString(Fixture("model-agent.btx"));
    BOOST_REQUIRE(fixture.find("btx://") == std::string::npos);
    BOOST_REQUIRE(fixture.ends_with(".btx") || fixture.ends_with(".BTX"));
    // One argv: the unsigned .btx path. Not a shell of mixed URI+file.
    const std::string cmd = ShellQuote(MODELNET_BTX_OPEN_PATH) + " " + ShellQuote(fixture);
    BOOST_REQUIRE(cmd.find("btx://") == std::string::npos);
    FILE* fp = popen(cmd.c_str(), "r");
    BOOST_REQUIRE(fp);
    std::string out;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp) != nullptr) {
        out.append(buf);
    }
    const int rc = pclose(fp);
    BOOST_REQUIRE_EQUAL(rc, 0);
    const bool inspect_fields = out.find("core_version") != std::string::npos ||
                                out.find("documents") != std::string::npos ||
                                out.find("agents_snippet") != std::string::npos;
    BOOST_CHECK_MESSAGE(inspect_fields, out);
    BOOST_CHECK(out.find("automatic_spend_atoms=1") == std::string::npos);
    BOOST_CHECK(out.find("\"automatic_spend_atoms\":1") == std::string::npos);
    BOOST_CHECK(out.find("spend=1") == std::string::npos);
    BOOST_CHECK(out.find("agents_md_write=false") != std::string::npos);
    BOOST_CHECK(out.find("action=preview-only") != std::string::npos);
#endif
    BOOST_CHECK(!fs::exists(m_path_root / "AGENTS.md"));
    BOOST_TEST_MESSAGE("AHP-API-04 remainder: OS MIME/xdg-open file association is not claimed");
}

BOOST_AUTO_TEST_CASE(ahp_api_05_install_trust_required_and_runtime_plan_only)
{
    const fs::path tmp = m_path_root / "ahp-api-ins";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("path", fs::PathToString(Fixture("model-agent.btx")));
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxclientinstall", arg), result, code, err));
    BOOST_CHECK(result["trust_required"].get_bool());
    BOOST_CHECK(!result["installs"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);

    UniValue catlg(UniValue::VOBJ);
    catlg.pushKV("distribution_id", "btx-model-tools");
    catlg.pushKV("independent_trust_ref", "operator-catalogue");
    catlg.pushKV("artifact_sha384", std::string(96, 'b'));
    catlg.pushKV("release_version", "0.34.8");
    catlg.pushKV("platform", "linux-x86_64");
    arg.pushKV("trusted_catalogue", catlg);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxclientinstall", arg), result, code, err), err);
    BOOST_CHECK(!result["installs"].get_bool());

    UniValue adapter(UniValue::VOBJ);
    adapter.pushKV("adapter_id", "llama.cpp");
    adapter.pushKV("verified_executable_digest", std::string(96, 'c'));
    adapter.pushKV("executable_path", "llama-cli");
    UniValue run(UniValue::VOBJ);
    arg.pushKV("trusted_adapter", adapter);
    result = UniValue(UniValue::VOBJ);
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("planbtxruntime", arg), result, code, err), err);
    BOOST_CHECK(!result["executes"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(ahp_api_06_create_unsigned_regtest_core_v2)
{
    const fs::path tmp = m_path_root / "ahp-api-create";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    UniValue payload;
    {
        std::ifstream in{Fixture("model-agent.json")};
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        BOOST_REQUIRE(payload.read(raw));
    }
    UniValue result;
    std::string code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("createbtxpackage", payload), result, code, err), err);
    BOOST_CHECK_EQUAL(result["core_version"].getInt<int>(), 2);
    BOOST_CHECK(result["unsigned"].get_bool());
    BOOST_CHECK(!result["magnet_analog"].get_bool());
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int>(), 0);
}

BOOST_AUTO_TEST_CASE(ahp_api_07_error_specificity)
{
    const fs::path tmp = m_path_root / "ahp-api-07";
    modelnet::ModelCatalog cat{tmp / "cat", 1 << 20};
    const fs::path fixture = Fixture("model-agent.btx");
    const auto bytes = ReadBytes(fixture);
    modelnet::DecodedBtxPackage pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(bytes, pkg, err), err);

    UniValue hf(UniValue::VOBJ);
    hf.pushKV("path", fs::PathToString(fixture));
    UniValue policy(UniValue::VOBJ);
    policy.pushKV("source_policy", "HUGGINGFACE");
    hf.pushKV("local_policy", policy);
    UniValue result;
    std::string code;
    const bool hf_ok = modelnet::DispatchHelperRpc(cat, Rpc("planbtxacquisition", hf), result, code, err);
    BOOST_CHECK_EQUAL(HelperErr(hf_ok, result, code), "NATIVE_SOURCES_UNAVAILABLE");

    UniValue empty_dest(UniValue::VOBJ);
    empty_dest.pushKV("destination", "");
    modelnet::AcquisitionPlan plan;
    std::string lib_code, lib_err;
    BOOST_CHECK(!modelnet::PlanBtxAcquisition(pkg.core, empty_dest, plan, lib_code, lib_err));
    BOOST_CHECK_EQUAL(lib_code, "DESTINATION_REQUIRED");
    BOOST_CHECK_NE(lib_code, "NATIVE_SOURCES_UNAVAILABLE");

    UniValue run(UniValue::VOBJ);
    run.pushKV("path", fs::PathToString(fixture));
    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    const bool run_ok = modelnet::DispatchHelperRpc(cat, Rpc("planbtxruntime", run), result, code, err);
    if (run_ok) {
        BOOST_CHECK(!result["executes"].get_bool());
    }
    BOOST_CHECK_EQUAL(HelperErr(run_ok, result, code), "MODEL_BYTES_UNVERIFIED");
    BOOST_CHECK_NE(HelperErr(run_ok, result, code), "NATIVE_SOURCES_UNAVAILABLE");
    BOOST_CHECK_NE(HelperErr(run_ok, result, code), "DESTINATION_REQUIRED");

    UniValue insp(UniValue::VOBJ);
    insp.pushKV("path", fs::PathToString(fixture));
    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    BOOST_REQUIRE_MESSAGE(modelnet::DispatchHelperRpc(cat, Rpc("inspectbtxpackage", insp), result, code, err), err);
    BOOST_CHECK(result["ok"].get_bool());

    result = UniValue(UniValue::VOBJ);
    code.clear();
    err.clear();
    const bool verify_ok = modelnet::DispatchHelperRpc(cat, Rpc("verifybtxpackage", insp), result, code, err);
    BOOST_CHECK_MESSAGE(
        !verify_ok || (result.exists("ok") && result["ok"].isBool() && !result["ok"].get_bool()),
        "verifybtxpackage must fail on unsigned fixture");
}

BOOST_AUTO_TEST_CASE(ahp_api_08_concurrent_parser)
{
    const auto bytes = ReadBytes(Fixture("model-agent.btx"));
    std::array<int, 4> ok{};
    std::array<std::string, 4> ids{};
    std::vector<std::thread> threads;
    threads.reserve(4);
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([&bytes, &ok, &ids, i] {
            modelnet::DecodedBtxPackage pkg;
            std::string err;
            const bool decoded = modelnet::DecodeBtxPackage(bytes, pkg, err);
            ok[i] = decoded ? 1 : 0;
            if (decoded) ids[i] = pkg.package_core_id.Hex();
        });
    }
    for (auto& t : threads) t.join();
    for (int i = 0; i < 4; ++i) {
        BOOST_CHECK_EQUAL(ok[i], 1);
        BOOST_CHECK_EQUAL(ids[i], kCoreId);
    }
    BOOST_TEST_MESSAGE("AHP-API-08: concurrent DecodeBtxPackage is not a DoS or rate-limit proof");
}

BOOST_AUTO_TEST_SUITE_END()
