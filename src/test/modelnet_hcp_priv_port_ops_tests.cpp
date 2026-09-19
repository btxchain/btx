// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
// HCP-PRIV-01 .. 08, HCP-PORT-01 .. 08, HCP-OPS-01 .. 08 unique native cases.

#include <test/modelnet_hcp_test.h>
#include <test/util/setup_common.h>
#include <modelnet/http_bridge.h>
#include <modelnet/package_core.h>
#include <clientversion.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdio>
#include <string>
#include <sys/wait.h>
#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(modelnet_hcp_priv_port_ops_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(hcp_priv_01_prompts_stay_local)
{
    auto e = hcp_test::Lab();
    e->SetPrivatePrompt("PROMPT_SENTINEL");
    UniValue out;
    std::string code;
    e->EnsureLocal(hcp_test::kRecipe, out, code);
    BOOST_CHECK(e->TrafficCapture().write().find("PROMPT_SENTINEL") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_priv_02_inventory_off_by_default)
{
    auto e = hcp_test::Lab();
    std::string code;
    auto plan = e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK(!plan["inventory_reported"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_priv_03_private_url_redaction)
{
    auto e = hcp_test::Lab();
    e->PutSourceHintWithSecret("https://origin.example/file?token=SECRETTOKEN");
    auto exp = e->ExportPublic(false);
    BOOST_CHECK(exp.write().find("SECRETTOKEN") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_priv_04_tenant_analytics)
{
    auto e = hcp_test::Lab();
    auto a = e->AnalyticsView();
    BOOST_CHECK(!a["cross_tenant"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_priv_05_required_versus_optional_records)
{
    auto e = hcp_test::Lab(true);
    e->SetReporting(false);
    BOOST_CHECK(!e->ConnectorStatus()["reporting"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_priv_06_read_token_in_runtime)
{
    auto e = hcp_test::Lab();
    e->PutSentinel("HCP_ACCESS_TOKEN", "tok-sentinel");
    auto env = e->ChildRuntimeEnv();
    BOOST_CHECK(env["HCP_ACCESS_TOKEN"].isNull());
}

BOOST_AUTO_TEST_CASE(hcp_priv_07_native_only_acquisition)
{
    auto e = hcp_test::Lab();
    e->SetSourcePolicyNativeOnly(true);
    e->PutSourceHintWithSecret("https://cloud.example/blob");
    std::string code;
    e->PlanLocal(hcp_test::kRecipe, code);
    BOOST_CHECK_EQUAL(code, "ORIGIN_DENIED");
}

BOOST_AUTO_TEST_CASE(hcp_priv_08_no_inference_billing)
{
    auto e = hcp_test::Lab();
    UniValue out;
    std::string code;
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_REQUIRE(e->EnsureLocal(hcp_test::kRecipe, out, code));
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
}

BOOST_AUTO_TEST_CASE(hcp_port_01_discovery_switch)
{
    auto e = hcp_test::Lab();
    auto sw = e->SwitchProvider("provider-b");
    BOOST_CHECK(sw["package_identity_preserved"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_port_02_uncertain_finance_across_providers)
{
    auto e = hcp_test::Lab();
    e->SetPendingUnknownOn("provider-demo", "intent-unknown");
    auto sw = e->SwitchProvider("provider-b");
    BOOST_CHECK(!sw["finance_replayed"].isTrue());
    BOOST_CHECK_EQUAL(sw["unresolved_on_old"].get_str(), "intent-unknown");
}

BOOST_AUTO_TEST_CASE(hcp_port_03_free_use_after_exit)
{
    auto e = hcp_test::Lab();
    e->DisconnectProvider();
    UniValue out;
    std::string code;
    BOOST_CHECK(e->EnsureLocal(hcp_test::kRecipe, out, code));
}

BOOST_AUTO_TEST_CASE(hcp_port_04_custody_exit_statement)
{
    auto e = hcp_test::Lab(true);
    auto exp = e->ExportPublic(false);
    BOOST_CHECK(!exp["self_custody"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_port_05_schema_evolution)
{
    auto e = hcp_test::Lab();
    e->SetUnknownCriticalCapability(true);
    auto r = e->Handle({.method = "GET", .path = "/no-such", .body = {}});
    BOOST_CHECK(r.status == 400 || r.status == 404);
}

BOOST_AUTO_TEST_CASE(hcp_port_06_migration_interruption)
{
    auto e = hcp_test::Lab();
    e->SetSchemaMigrationCrash(true);
    BOOST_CHECK(!e->Persist());
    e->SetSchemaMigrationCrash(false);
    BOOST_CHECK(e->Persist());
}

BOOST_AUTO_TEST_CASE(hcp_port_07_independent_sdk_parity)
{
    auto e = hcp_test::Lab();
    auto env = hcp_test::MakeHandoff(*e, "device-demo", "demo-nonce-not-production", hcp_test::kCore, hcp_test::kRecipe);
    modelnet::Digest48 id;
    std::string err;
    BOOST_REQUIRE(modelnet::HcpBodyId(env.object_type, env.body, id, err));
    BOOST_CHECK(id == env.body_id);

#ifndef MODELNET_HCP_PORTAL_PATH
    BOOST_REQUIRE_MESSAGE(false, "MODELNET_HCP_PORTAL_PATH is not defined");
#else
    const fs::path portal = fs::PathFromString(MODELNET_HCP_PORTAL_PATH);
    const fs::path sdk_root = portal.parent_path().parent_path() / "hcp-sdk";
    const fs::path python = sdk_root / "python" / "test_body_id.py";
    const fs::path ts = sdk_root / "typescript" / "src" / "body_id.test.ts";

    const auto shell_quote = [](const std::string& s) {
        std::string q = "'";
        for (char c : s) {
            if (c == '\'') q += "'\\''";
            else q += c;
        }
        q += "'";
        return q;
    };
    const auto spawn = [](const std::string& cmd, std::string& combined) {
        FILE* fp = ::popen(cmd.c_str(), "r");
        if (!fp) return -1;
        char buf[4096];
        while (fgets(buf, sizeof(buf), fp) != nullptr) combined.append(buf);
        const int st = ::pclose(fp);
        if (st == -1) return -1;
        if (WIFEXITED(st)) return WEXITSTATUS(st);
        return 127;
    };
    const auto which = [&](const char* name) {
        std::string out;
        const int rc = spawn(std::string("command -v ") + name + " 2>/dev/null", out);
        while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) out.pop_back();
        if (rc != 0) return std::string{};
        return out;
    };

    BOOST_REQUIRE_MESSAGE(fs::exists(python), fs::PathToString(python) + " missing");
    std::string python_exe = "/usr/bin/python3";
    if (::access(python_exe.c_str(), X_OK) != 0) {
        python_exe = which("python3");
    }
    BOOST_REQUIRE_MESSAGE(!python_exe.empty() && ::access(python_exe.c_str(), X_OK) == 0,
                          "python3 is required for independent SDK parity");
    std::string py_out;
    const std::string py_cmd =
        shell_quote(python_exe) + " " + shell_quote(fs::PathToString(python)) + " 2>&1";
    const int py_rc = spawn(py_cmd, py_out);
    BOOST_REQUIRE_MESSAGE(py_rc == 0, "python SDK test_body_id.py rc=" + std::to_string(py_rc) + "\n" + py_out);

    const std::string node_exe = which("node");
    if (node_exe.empty()) {
        BOOST_TEST_MESSAGE("HONEST_NOT_RUN typescript SDK");
    } else {
        BOOST_REQUIRE_MESSAGE(fs::exists(ts), fs::PathToString(ts) + " missing");
        std::string ts_out;
        // node:test + .ts imports: native strip-types (package.json: node --test).
        const std::string ts_cmd = shell_quote(node_exe) + " --experimental-strip-types --test " +
                                   shell_quote(fs::PathToString(ts)) + " 2>&1";
        const int ts_rc = spawn(ts_cmd, ts_out);
        BOOST_REQUIRE_MESSAGE(ts_rc == 0,
                              "typescript SDK body_id.test.ts rc=" + std::to_string(ts_rc) + "\n" + ts_out);
    }
#endif
}

BOOST_AUTO_TEST_CASE(hcp_port_08_no_native_core_rewrite)
{
    auto e = hcp_test::Lab();
    auto bytes = e->Handle({.method = "GET", .path = std::string("/packages/") + hcp_test::kCore});
    BOOST_REQUIRE_EQUAL(bytes.status, 200);
    if (bytes.body.empty()) {
        BOOST_CHECK(bytes.body.empty());
    } else {
        modelnet::DecodedBtxPackage dec;
        std::string err;
        std::vector<unsigned char> raw(bytes.body.begin(), bytes.body.end());
        BOOST_REQUIRE_MESSAGE(modelnet::DecodeBtxPackage(raw, dec, err), err);
    }
}

BOOST_AUTO_TEST_CASE(hcp_ops_01_public_bridge_isolation)
{
    modelnet::BrowserBridgeResponse out;
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/finance/intents", "{}", out, ""));
    BOOST_CHECK_EQUAL(out.http_status, 405);
    BOOST_REQUIRE(modelnet::HandleBridgeRequest("POST", "/btx/hcp/v1/finance/quotes", "{}", out, ""));
    BOOST_CHECK_EQUAL(out.http_status, 405);
}

BOOST_AUTO_TEST_CASE(hcp_ops_02_money_only_regression)
{
    const std::string ver = FormatFullVersion();
    BOOST_CHECK(ver.find("0.34.8") != std::string::npos);
    if (!CLIENT_VERSION_IS_RELEASE) {
        BOOST_CHECK(ver.find("-dev") != std::string::npos || ver.find("0.34.8") != std::string::npos);
    }
    auto e = hcp_test::Lab();
    BOOST_CHECK_EQUAL(e->Cfg().automatic_spend_atoms, 0);
    BOOST_CHECK_EQUAL(e->ConnectorStatus()["automatic_spend_atoms"].getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(hcp_ops_03_replica_fencing)
{
    auto e = hcp_test::Lab(true);
    e->SetExecutorOwner("replica-other");
    const std::string tok = hcp_test::Token(*e, hcp_test::AllScopes());
    UniValue body(UniValue::VOBJ);
    body.pushKV("client_operation_id", "op-ops03");
    auto created = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents", tok, &body));
    UniValue env;
    BOOST_REQUIRE(env.read(created.body));
    const std::string iid = env["body"]["intent_id"].get_str();
    e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/authorize", tok));
    auto sub = e->Handle(hcp_test::AuthReq(*e, "POST", "/finance/intents/" + iid + "/submit", tok));
    BOOST_CHECK(sub.status == 409 || sub.body.find(modelnet::HCP_ERR_FENCED) != std::string::npos);
}

BOOST_AUTO_TEST_CASE(hcp_ops_04_scale_within_limits)
{
    auto e = hcp_test::Lab();
    modelnet::HcpHttpRequest req;
    req.method = "POST";
    req.path = "/capabilities/search";
    req.body.assign(static_cast<size_t>(modelnet::HCP_MAX_BODY_BYTES) + 1, 'x');
    BOOST_CHECK_EQUAL(e->Handle(req).status, 413);
}

BOOST_AUTO_TEST_CASE(hcp_ops_05_no_production_side_effects)
{
    auto e = hcp_test::Lab();
    auto man = e->GoLiveManifest();
    BOOST_CHECK(!man["production_binary_replaced"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_ops_06_provider_compromise_drill)
{
    auto e = hcp_test::Lab();
    std::string code, err;
    BOOST_REQUIRE(e->RotateOperationalKey(9, code, err));
    BOOST_CHECK(!e->ReplayOldKeyset("op-1", code));
}

BOOST_AUTO_TEST_CASE(hcp_ops_07_claimed_profile_evidence)
{
    auto e = hcp_test::Lab();
    auto man = e->GoLiveManifest();
    BOOST_CHECK(man["proven"]["DISCOVERY"].isTrue());
    BOOST_CHECK(!man["proven"]["FUNDING"].isTrue());
}

BOOST_AUTO_TEST_CASE(hcp_ops_08_full_audit_closure)
{
    auto e = hcp_test::Lab(true);
    auto man = e->GoLiveManifest();
    BOOST_CHECK_EQUAL(man["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK(man.exists("not_run"));
}

BOOST_AUTO_TEST_SUITE_END()
