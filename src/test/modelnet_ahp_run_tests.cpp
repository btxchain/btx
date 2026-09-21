// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// AHP-RUN-01  Plan is not execution
// AHP-RUN-02  Authorized local smoke (plan-level; process start NOT_RUN)
// AHP-RUN-03  No arbitrary shell
// AHP-RUN-04  No model custom code
// AHP-RUN-05  Network containment (plan-level)
// AHP-RUN-06  Credentials and inherited environment (plan-level)
// AHP-RUN-07  OOM and cancellation (plan-level bounds; live OOM NOT_RUN)
// AHP-RUN-08  Changed executable (plan binds digest; live TOCTOU NOT_RUN)

#include <modelnet/package_core.h>
#include <modelnet/package_runtime.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstdlib>
#include <optional>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_ahp_run_tests, BasicTestingSetup)

namespace {

std::string Hex96(char fill)
{
    return std::string(96, fill);
}

UniValue MinimalCore(const std::string& adapter_id = "llama.cpp")
{
    UniValue params(UniValue::VOBJ);
    params.pushKV("context_tokens", 2048);
    params.pushKV("threads", 4);
    UniValue profile(UniValue::VOBJ);
    profile.pushKV("profile_id", "local-llama");
    profile.pushKV("adapter_id", adapter_id);
    profile.pushKV("adapter_schema", "local-cli-v1");
    UniValue vids(UniValue::VARR);
    vids.push_back("demo-q4");
    profile.pushKV("variant_ids", vids);
    profile.pushKV("backend", "cpu");
    profile.pushKV("mode", "CLI");
    profile.pushKV("parameters", params);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah(UniValue::VOBJ);
    ah.pushKV("version", 1);
    ah.pushKV("entry_document", "AGENTS.md");
    ah.pushKV("runtime_profiles", profiles);
    UniValue res(UniValue::VOBJ);
    res.pushKV("kind", "MODEL");
    res.pushKV("id", Hex96('a'));
    UniValue resources(UniValue::VARR);
    resources.push_back(res);
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 2);
    core.pushKV("network", "REGTEST");
    core.pushKV("package_type", "MODEL");
    core.pushKV("label", "ahp-run");
    core.pushKV("resources", resources);
    core.pushKV("agent_handoff", ah);
    return core;
}

UniValue ReadyReceipt(const UniValue& core, const std::string& leased = "/tmp/btx-ahp-run/model.gguf")
{
    modelnet::Digest48 cid;
    std::string err;
    BOOST_REQUIRE(modelnet::PackageCoreId(core, cid, err));
    UniValue rids(UniValue::VARR);
    rids.push_back(Hex96('a'));
    UniValue paths(UniValue::VARR);
    paths.push_back(leased);
    UniValue rec(UniValue::VOBJ);
    rec.pushKV("schema_version", 1);
    rec.pushKV("receipt_id", Hex96('c'));
    rec.pushKV("package_core_id", cid.Hex());
    rec.pushKV("plan_id", Hex96('d'));
    rec.pushKV("resource_ids", rids);
    rec.pushKV("state", "MODEL_READY");
    rec.pushKV("local_paths", paths);
    rec.pushKV("leased_path", leased);
    rec.pushKV("manifest_verified", true);
    rec.pushKV("file_bytes_verified", true);
    rec.pushKV("lease_id", "lease-1");
    rec.pushKV("runtime_executed", false);
    rec.pushKV("created_at_ms", "1");
    return rec;
}

UniValue TrustedAdapter(const std::string& adapter_id = "llama.cpp")
{
    UniValue t(UniValue::VOBJ);
    t.pushKV("adapter_id", adapter_id);
    t.pushKV("profile_id", "local-llama");
    t.pushKV("adapter_schema", "local-cli-v1");
    t.pushKV("executable_path", "/opt/btx-test/llama-cli");
    t.pushKV("verified_executable_digest", Hex96('b'));
    t.pushKV("working_directory", "/tmp/btx-ahp-run");
    t.pushKV("maximum_memory_bytes", "2147483648");
    t.pushKV("maximum_seconds", 60);
    return t;
}

UniValue CoreWithMode(const std::string& mode)
{
    UniValue core = MinimalCore();
    UniValue profile = core["agent_handoff"]["runtime_profiles"][0];
    profile.pushKV("mode", mode);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah = core["agent_handoff"];
    ah.pushKV("runtime_profiles", profiles);
    core.pushKV("agent_handoff", ah);
    return core;
}

UniValue CoreWithParams(const UniValue& params)
{
    UniValue core = MinimalCore();
    UniValue profile = core["agent_handoff"]["runtime_profiles"][0];
    profile.pushKV("parameters", params);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah = core["agent_handoff"];
    ah.pushKV("runtime_profiles", profiles);
    core.pushKV("agent_handoff", ah);
    return core;
}

bool JsonContains(const UniValue& v, const std::string& needle)
{
    if (v.isStr() && v.get_str().find(needle) != std::string::npos) return true;
    if (v.isObject()) {
        for (const auto& k : v.getKeys()) {
            if (k.find(needle) != std::string::npos) return true;
            if (JsonContains(v[k], needle)) return true;
        }
    } else if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (JsonContains(e, needle)) return true;
        }
    }
    return false;
}

} // namespace

BOOST_AUTO_TEST_CASE(ahp_run_01_plan_is_not_execution)
{
    const UniValue core = MinimalCore();
    const UniValue receipt = ReadyReceipt(core);
    const UniValue trusted = TrustedAdapter();
    modelnet::RuntimePlan plan;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, trusted, plan, err_code, err), err);
    BOOST_CHECK(!plan.executes);
    BOOST_CHECK(plan.json.exists("executes"));
    BOOST_CHECK(plan.json["executes"].isFalse());
    BOOST_CHECK_EQUAL(plan.leased_path, "/tmp/btx-ahp-run/model.gguf");
    BOOST_CHECK_EQUAL(plan.adapter_id, "llama.cpp");
    BOOST_CHECK_EQUAL(plan.profile_id, "local-llama");
    BOOST_CHECK_EQUAL(plan.plan_id_hex.size(), 96U);
    BOOST_CHECK_EQUAL(plan.json["plan_id"].get_str(), plan.plan_id_hex);
    BOOST_CHECK_EQUAL(plan.json["network_policy"].get_str(), "NONE");
    BOOST_REQUIRE_GE(plan.argv.size(), 3U);
    BOOST_CHECK_EQUAL(plan.argv[0], "/opt/btx-test/llama-cli");
    BOOST_CHECK_EQUAL(plan.argv[1], "-m");
    BOOST_CHECK_EQUAL(plan.argv[2], plan.leased_path);
    BOOST_CHECK(std::find(plan.argv.begin(), plan.argv.end(), "-c") != plan.argv.end());
    BOOST_CHECK(std::find(plan.argv.begin(), plan.argv.end(), "sh") == plan.argv.end());

    UniValue want_exec = trusted;
    want_exec.pushKV("executes", true);
    modelnet::RuntimePlan blocked;
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, receipt, want_exec, blocked, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "EXECUTION_APPROVAL_REQUIRED");
    BOOST_CHECK(!blocked.executes);

    UniValue core_exec = core;
    core_exec.pushKV("executes", true);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core_exec, receipt, trusted, blocked, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "EXECUTION_APPROVAL_REQUIRED");

    UniValue unverified = receipt;
    unverified.pushKV("file_bytes_verified", false);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, unverified, trusted, blocked, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "MODEL_BYTES_UNVERIFIED");

    UniValue no_lease = receipt;
    no_lease.pushKV("leased_path", "");
    UniValue empty_paths(UniValue::VARR);
    no_lease.pushKV("local_paths", empty_paths);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, no_lease, trusted, blocked, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "MODEL_BYTES_UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(ahp_run_03_no_arbitrary_shell)
{
    std::string err;
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"sh", "-c", "curl http://example/x"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"/bin/sh", "-c", "id"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"bash", "-c", "python -c import os"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"python", "-c", "import os"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"python3", "-c", "print(1)"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"curl", "https://evil.example"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"/opt/btx-test/llama-cli", "-m", "$HOME/model.gguf"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/x", "--evil-flag", "1"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/x;id"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/run.sh"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed("sh", {"/opt/btx-test/llama-cli", "-m", "/tmp/m.gguf"}, err));

    BOOST_CHECK(modelnet::RuntimeArgvAllowed(
        "llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/btx-ahp-run/model.gguf", "-c", "2048", "-t", "4"}, err));

    UniValue core = MinimalCore();
    UniValue params(UniValue::VOBJ);
    params.pushKV("context_tokens", 2048);
    params.pushKV("--host", 0);
    UniValue profile = core["agent_handoff"]["runtime_profiles"][0];
    profile.pushKV("parameters", params);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah = core["agent_handoff"];
    ah.pushKV("runtime_profiles", profiles);
    core.pushKV("agent_handoff", ah);

    modelnet::RuntimePlan plan;
    std::string err_code;
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, ReadyReceipt(core), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue core_shell = MinimalCore();
    UniValue p2(UniValue::VOBJ);
    p2.pushKV("shell", 1);
    UniValue pr2 = core_shell["agent_handoff"]["runtime_profiles"][0];
    pr2.pushKV("parameters", p2);
    UniValue ps2(UniValue::VARR);
    ps2.push_back(pr2);
    UniValue ah2 = core_shell["agent_handoff"];
    ah2.pushKV("runtime_profiles", ps2);
    core_shell.pushKV("agent_handoff", ah2);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core_shell, ReadyReceipt(core_shell), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");
}

BOOST_AUTO_TEST_CASE(ahp_run_04_no_model_custom_code)
{
    UniValue core = MinimalCore();
    UniValue params(UniValue::VOBJ);
    params.pushKV("trust_remote_code", 1);
    UniValue profile = core["agent_handoff"]["runtime_profiles"][0];
    profile.pushKV("parameters", params);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah = core["agent_handoff"];
    ah.pushKV("runtime_profiles", profiles);
    core.pushKV("agent_handoff", ah);

    modelnet::RuntimePlan plan;
    std::string err_code, err;
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, ReadyReceipt(core), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue core_plug = MinimalCore();
    UniValue p2(UniValue::VOBJ);
    p2.pushKV("plugins", 1);
    UniValue pr2 = core_plug["agent_handoff"]["runtime_profiles"][0];
    pr2.pushKV("parameters", p2);
    UniValue ps2(UniValue::VARR);
    ps2.push_back(pr2);
    UniValue ah2 = core_plug["agent_handoff"];
    ah2.pushKV("runtime_profiles", ps2);
    core_plug.pushKV("agent_handoff", ah2);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core_plug, ReadyReceipt(core_plug), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    // Labels without a matching trusted_adapter record do not establish support.
    const UniValue labeled = MinimalCore("vllm");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(labeled, ReadyReceipt(labeled), TrustedAdapter("llama.cpp"), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue empty(UniValue::VOBJ);
    const UniValue llama_core = MinimalCore("llama.cpp");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(llama_core, ReadyReceipt(llama_core), empty, plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue label_only(UniValue::VOBJ);
    label_only.pushKV("adapter_id", "llama.cpp");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(llama_core, ReadyReceipt(llama_core), label_only, plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    for (const char* id : {"ollama", "mlx", "vllm", "llama.cpp"}) {
        UniValue c = MinimalCore(id);
        BOOST_CHECK(!modelnet::PlanBtxRuntime(c, ReadyReceipt(c), UniValue(UniValue::VOBJ), plan, err_code, err));
        BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");
    }

    const UniValue py_receipt = ReadyReceipt(llama_core, "/tmp/btx-ahp-run/model.py");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(llama_core, py_receipt, TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "MODEL_BYTES_UNVERIFIED");
}

BOOST_AUTO_TEST_CASE(ahp_run_02_authorized_local_smoke_plan)
{
    // AHP-RUN-02 plan-level: exact local path + finite limits produce a typed
    // smoke plan with no remote inference. PlanBtxRuntime never starts a process.
    const UniValue core = MinimalCore();
    const UniValue receipt = ReadyReceipt(core, "/tmp/btx-ahp-run/model.gguf");
    UniValue trusted = TrustedAdapter();
    trusted.pushKV("maximum_memory_bytes", "268435456");
    trusted.pushKV("maximum_seconds", 15);

    modelnet::RuntimePlan plan;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, trusted, plan, err_code, err), err);
    BOOST_CHECK(!plan.executes);
    BOOST_CHECK(plan.json["executes"].isFalse());
    BOOST_CHECK_EQUAL(plan.leased_path, "/tmp/btx-ahp-run/model.gguf");
    BOOST_CHECK_EQUAL(plan.adapter_id, "llama.cpp");
    BOOST_CHECK_EQUAL(plan.json["network_policy"].get_str(), "NONE");
    BOOST_CHECK_EQUAL(plan.json["maximum_memory_bytes"].get_str(), "268435456");
    BOOST_CHECK_EQUAL(plan.json["maximum_seconds"].getInt<int>(), 15);
    BOOST_CHECK_EQUAL(plan.argv[0], "/opt/btx-test/llama-cli");
    BOOST_CHECK_EQUAL(plan.argv[2], plan.leased_path);
    BOOST_CHECK(!JsonContains(plan.json, "://"));
    BOOST_CHECK(!JsonContains(plan.json, "huggingface"));
    BOOST_CHECK(std::find(plan.argv.begin(), plan.argv.end(), "curl") == plan.argv.end());

    UniValue want_exec = trusted;
    want_exec.pushKV("executes", true);
    modelnet::RuntimePlan blocked;
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, receipt, want_exec, blocked, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "EXECUTION_APPROVAL_REQUIRED");
    BOOST_CHECK(!blocked.executes);
    BOOST_TEST_MESSAGE("AHP-RUN-02 remainder NOT_RUN: PlanBtxRuntime does not spawn llama-cli; no helper execute");
}

BOOST_AUTO_TEST_CASE(ahp_run_05_network_containment)
{
    // AHP-RUN-05 plan-level: default CLI is network NONE; LOOPBACK_SERVICE is
    // LOOPBACK_ONLY; outbound host/bind/URL flags are rejected.
    std::string err;
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed(
        "llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/m.gguf", "--host", "0.0.0.0"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed(
        "llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/m.gguf", "--bind", "1.2.3.4"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed(
        "llama.cpp", {"/opt/btx-test/llama-cli", "-m", "/tmp/m.gguf", "--port", "8080"}, err));
    BOOST_CHECK(!modelnet::RuntimeArgvAllowed(
        "llama.cpp", {"/opt/btx-test/llama-cli", "-m", "https://inference.example/v1"}, err));

    const UniValue cli = MinimalCore();
    modelnet::RuntimePlan plan;
    std::string err_code;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(cli, ReadyReceipt(cli), TrustedAdapter(), plan, err_code, err), err);
    BOOST_CHECK_EQUAL(plan.json["network_policy"].get_str(), "NONE");

    const UniValue loop = CoreWithMode("LOOPBACK_SERVICE");
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(loop, ReadyReceipt(loop), TrustedAdapter(), plan, err_code, err), err);
    BOOST_CHECK_EQUAL(plan.json["network_policy"].get_str(), "LOOPBACK_ONLY");

    const UniValue remote = CoreWithMode("REMOTE");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(remote, ReadyReceipt(remote), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue host_params(UniValue::VOBJ);
    host_params.pushKV("context_tokens", 2048);
    host_params.pushKV("host", 0);
    const UniValue host_core = CoreWithParams(host_params);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(host_core, ReadyReceipt(host_core), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");

    UniValue bind_params(UniValue::VOBJ);
    bind_params.pushKV("bind", 1);
    const UniValue bind_core = CoreWithParams(bind_params);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(bind_core, ReadyReceipt(bind_core), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");
    BOOST_TEST_MESSAGE("AHP-RUN-05 remainder NOT_RUN: live non-loopback bind is not spawned");
}

BOOST_AUTO_TEST_CASE(ahp_run_06_credentials_not_inherited_into_plan)
{
    // AHP-RUN-06 plan-level: parent/cloud/wallet sentinels and package env must
    // not appear in the typed plan. Child spawn stays NOT_RUN.
    auto snapshot = [](const char* key) -> std::optional<std::string> {
        const char* v = ::getenv(key);
        if (!v) return std::nullopt;
        return std::string(v);
    };
    auto restore = [](const char* key, const std::optional<std::string>& previous) {
        if (previous) {
            BOOST_REQUIRE_EQUAL(::setenv(key, previous->c_str(), 1), 0);
        } else {
            BOOST_REQUIRE_EQUAL(::unsetenv(key), 0);
        }
    };
    const auto old_hf = snapshot("HF_TOKEN");
    const auto old_s3 = snapshot("AWS_SECRET_ACCESS_KEY");
    const auto old_w = snapshot("BTX_WALLET_SEED");
    BOOST_REQUIRE_EQUAL(::setenv("HF_TOKEN", "HF_TEST_SENTINEL", 1), 0);
    BOOST_REQUIRE_EQUAL(::setenv("AWS_SECRET_ACCESS_KEY", "S3_TEST_SENTINEL", 1), 0);
    BOOST_REQUIRE_EQUAL(::setenv("BTX_WALLET_SEED", "WALLET_TEST_SENTINEL", 1), 0);

    const UniValue core = MinimalCore();
    UniValue trusted = TrustedAdapter();
    UniValue env(UniValue::VOBJ);
    env.pushKV("HF_TOKEN", "HF_TEST_SENTINEL");
    env.pushKV("AWS_SECRET_ACCESS_KEY", "S3_TEST_SENTINEL");
    env.pushKV("BTX_WALLET_SEED", "WALLET_TEST_SENTINEL");
    trusted.pushKV("env", env);

    modelnet::RuntimePlan plan;
    std::string err_code, err;
    const bool planned = modelnet::PlanBtxRuntime(core, ReadyReceipt(core), trusted, plan, err_code, err);
    restore("HF_TOKEN", old_hf);
    restore("AWS_SECRET_ACCESS_KEY", old_s3);
    restore("BTX_WALLET_SEED", old_w);
    BOOST_REQUIRE_MESSAGE(planned, err);

    BOOST_CHECK(!plan.json.exists("env"));
    BOOST_CHECK(!plan.json.exists("HF_TOKEN"));
    BOOST_CHECK(!JsonContains(plan.json, "HF_TEST_SENTINEL"));
    BOOST_CHECK(!JsonContains(plan.json, "S3_TEST_SENTINEL"));
    BOOST_CHECK(!JsonContains(plan.json, "WALLET_TEST_SENTINEL"));
    for (const auto& a : plan.argv) {
        BOOST_CHECK(a.find("HF_TEST_SENTINEL") == std::string::npos);
        BOOST_CHECK(a.find("S3_TEST_SENTINEL") == std::string::npos);
        BOOST_CHECK(a.find("WALLET_TEST_SENTINEL") == std::string::npos);
    }

    UniValue core_env = MinimalCore();
    UniValue profile = core_env["agent_handoff"]["runtime_profiles"][0];
    profile.pushKV("env", env);
    UniValue profiles(UniValue::VARR);
    profiles.push_back(profile);
    UniValue ah = core_env["agent_handoff"];
    ah.pushKV("runtime_profiles", profiles);
    core_env.pushKV("agent_handoff", ah);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core_env, ReadyReceipt(core_env), TrustedAdapter(), plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "RUNTIME_ADAPTER_UNSUPPORTED");
    BOOST_TEST_MESSAGE("AHP-RUN-06 remainder NOT_RUN: child process environment is not sampled; no spawn");
}

BOOST_AUTO_TEST_CASE(ahp_run_07_oom_and_cancel_bounds_without_success_receipt)
{
    // AHP-RUN-07 plan-level: memory/time bounds are part of the plan; a failed
    // or already-executed receipt cannot be turned into a success plan.
    const UniValue core = MinimalCore();
    UniValue trusted = TrustedAdapter();
    trusted.pushKV("maximum_memory_bytes", "1048576");
    trusted.pushKV("maximum_seconds", 5);

    modelnet::RuntimePlan plan;
    std::string err_code, err;
    UniValue receipt = ReadyReceipt(core);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, trusted, plan, err_code, err), err);
    BOOST_CHECK(!plan.executes);
    BOOST_CHECK_EQUAL(plan.json["maximum_memory_bytes"].get_str(), "1048576");
    BOOST_CHECK_EQUAL(plan.json["maximum_seconds"].getInt<int>(), 5);
    BOOST_CHECK(receipt["runtime_executed"].isFalse());

    UniValue already = receipt;
    already.pushKV("runtime_executed", true);
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, already, trusted, plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "EXECUTION_APPROVAL_REQUIRED");

    UniValue failed = receipt;
    failed.pushKV("state", "FAILED");
    BOOST_CHECK(!modelnet::PlanBtxRuntime(core, failed, trusted, plan, err_code, err));
    BOOST_CHECK_EQUAL(err_code, "MODEL_BYTES_UNVERIFIED");
    BOOST_TEST_MESSAGE("AHP-RUN-07 remainder NOT_RUN: live OOM/interrupt cleanup needs an isolated adapter process");
}

BOOST_AUTO_TEST_CASE(ahp_run_08_changed_executable_invalidates_plan)
{
    // AHP-RUN-08 plan-level: verified_executable_digest is bound into the plan.
    // A substituted digest or path produces a different plan_id.
    const UniValue core = MinimalCore();
    const UniValue receipt = ReadyReceipt(core);

    UniValue a_tr = TrustedAdapter();
    UniValue b_tr = TrustedAdapter();
    b_tr.pushKV("verified_executable_digest", Hex96('e'));
    UniValue c_tr = TrustedAdapter();
    c_tr.pushKV("executable_path", "/opt/btx-test/llama-cli-evil");

    modelnet::RuntimePlan a, b, c;
    std::string err_code, err;
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, a_tr, a, err_code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, b_tr, b, err_code, err), err);
    BOOST_REQUIRE_MESSAGE(modelnet::PlanBtxRuntime(core, receipt, c_tr, c, err_code, err), err);
    BOOST_CHECK_EQUAL(a.json["verified_executable_digest"].get_str(), Hex96('b'));
    BOOST_CHECK_EQUAL(b.json["verified_executable_digest"].get_str(), Hex96('e'));
    BOOST_CHECK(a.plan_id_hex != b.plan_id_hex);
    BOOST_CHECK(a.plan_id_hex != c.plan_id_hex);
    BOOST_CHECK_EQUAL(a.json["executable_path"].get_str(), "/opt/btx-test/llama-cli");
    BOOST_CHECK_EQUAL(c.json["executable_path"].get_str(), "/opt/btx-test/llama-cli-evil");
    BOOST_CHECK(!a.executes);
    BOOST_CHECK(!b.executes);
    BOOST_TEST_MESSAGE("AHP-RUN-08 remainder NOT_RUN: live TOCTOU revalidation at spawn is not in PlanBtxRuntime");
}

BOOST_AUTO_TEST_SUITE_END()
