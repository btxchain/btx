// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// BTX-SPEC-0348-CAPABILITY-01 — RUN family (native).
//   JIT-RUN-01  CPU baseline (synthetic-cpu-fixture)
//   JIT-RUN-02  CUDA path (absence / live loader NOT_RUN; probe honesty)
//   JIT-RUN-03  ROCm path (absence / live loader NOT_RUN; probe honesty)
//   JIT-RUN-04  Metal/MLX path (absence / live loader NOT_RUN; probe honesty)
//   JIT-RUN-05  Unknown adapter parameters
//   JIT-RUN-06  Sleep discarded state
//   JIT-RUN-07  Plugin ABI mismatch
//
// Coordinator owns CMakeLists.txt. Hardware PASS is never faked.

#include <modelnet/capability.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <univalue.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

namespace modelnet {
std::vector<RuntimeAdapterStatus> ProbeAcceleratedAdapters();
bool ProbeRuntimeAdapterAbi(const std::string& candidate_abi, std::string& supported_path, std::string& err_code,
                            std::string& err);
bool LoadTrustedRuntime(const std::string& runtime_id, Span<const unsigned char> verified, const UniValue& typed_params,
                        ReadyReceipt& receipt, std::string& err_code, std::string& err);
bool SleepRuntimePreserveWeights(const std::string& lease_id, UniValue& status, std::string& err_code, std::string& err);
bool WakeRuntimeRebuildKv(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err);
bool WakeRuntimeRemapOnly(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err);
} // namespace modelnet

BOOST_FIXTURE_TEST_SUITE(modelnet_jit_run_tests, BasicTestingSetup)

namespace {

Span<const unsigned char> TinyVerified()
{
    static const unsigned char k[] = {'t', 'i', 'n', 'y', '-', 'c', 'p', 'u', '-', 'f', 'i', 'x', 't', 'u', 'r', 'e'};
    return Span<const unsigned char>{k, sizeof(k)};
}

UniValue CpuParams()
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
    p.pushKV("backend", "CPU");
    return p;
}

const modelnet::RuntimeAdapterStatus* FindBackend(const std::vector<modelnet::RuntimeAdapterStatus>& v,
                                                  const std::string& backend)
{
    for (const auto& s : v) {
        if (s.backend == backend) return &s;
    }
    return nullptr;
}

void AssertStubNeverTrue(const std::vector<modelnet::RuntimeAdapterStatus>& v)
{
    BOOST_REQUIRE(!v.empty());
    for (const auto& s : v) {
        BOOST_CHECK_MESSAGE(!s.stub, s.runtime_id + " stub=true is dishonest");
    }
}

void AssertAccelHonesty(const std::vector<modelnet::RuntimeAdapterStatus>& v)
{
    AssertStubNeverTrue(v);
    for (const auto& s : v) {
        if (!s.present) {
            BOOST_CHECK_MESSAGE(s.detail.find("NOT_RUN") != std::string::npos,
                                s.runtime_id + " absent hardware must detail NOT_RUN: " + s.detail);
        }
    }
}

void AssertUnknownParamsRejected(const std::string& runtime_id)
{
    auto reject = [&](const UniValue& p, const char* what) {
        modelnet::ReadyReceipt rec;
        std::string code, err;
        BOOST_CHECK_MESSAGE(!modelnet::LoadTrustedRuntime(runtime_id, TinyVerified(), p, rec, code, err), what);
        BOOST_CHECK_EQUAL(code, "UNKNOWN_ADAPTER_PARAMETER");
        BOOST_CHECK(!rec.smoke_passed);
        BOOST_CHECK(rec.achieved != modelnet::ReadinessTarget::FIRST_USEFUL_RESULT || !rec.smoke_passed);
    };

    UniValue exe(UniValue::VOBJ);
    exe.pushKV("executable_path", "/tmp/evil-llama");
    reject(exe, "executable_path");

    UniValue ld(UniValue::VOBJ);
    ld.pushKV("LD_PRELOAD", "/tmp/evil.so");
    reject(ld, "LD_PRELOAD");

    UniValue ld2(UniValue::VOBJ);
    ld2.pushKV("ld_preload", "/tmp/evil.so");
    reject(ld2, "ld_preload");

    UniValue unk(UniValue::VOBJ);
    unk.pushKV("unrecognized_flag", "--steal-authority");
    reject(unk, "unrecognized_flag");

    UniValue flags(UniValue::VOBJ);
    flags.pushKV("evil", "1");
    UniValue wrapped(UniValue::VOBJ);
    wrapped.pushKV("flags", flags);
    reject(wrapped, "unrecognized flags object");
}

void AssertAccelCase(const char* spec_id, const char* backend, const char* runtime_id, const char* backend_param)
{
    const auto exec_probe = modelnet::ProbeRuntimeAdapters();
    AssertStubNeverTrue(exec_probe);
    const auto accel = modelnet::ProbeAcceleratedAdapters();
    AssertAccelHonesty(accel);
    const auto* hw = FindBackend(accel, backend);
    BOOST_REQUIRE(hw != nullptr);
    BOOST_CHECK(!hw->stub);
    if (!hw->present) {
        BOOST_TEST_MESSAGE(std::string(spec_id) + " NOT_RUN: " + backend + " not actually usable (" + hw->detail + ")");
        BOOST_CHECK(hw->detail.find("NOT_RUN") != std::string::npos);
    } else {
        BOOST_TEST_MESSAGE(std::string(spec_id) + " " + backend +
                           " probe present; live loader NOT_RUN (no mock PASS, production GPU not contended)");
    }

    UniValue p(UniValue::VOBJ);
    p.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
    p.pushKV("backend", backend_param);
    modelnet::ReadyReceipt rec;
    std::string code, err;
    const bool ok = modelnet::LoadTrustedRuntime(runtime_id, TinyVerified(), p, rec, code, err);
    BOOST_CHECK(!ok);
    BOOST_CHECK(!rec.smoke_passed);
    BOOST_CHECK(err.find("NOT_RUN") != std::string::npos || code.find("NOT_RUN") != std::string::npos);
    AssertUnknownParamsRejected(runtime_id);
}

} // namespace

BOOST_AUTO_TEST_CASE(JIT_RUN_01)
{
    BOOST_TEST_MESSAGE("JIT-RUN-01 CPU baseline");
    const auto probes = modelnet::ProbeRuntimeAdapters();
    AssertStubNeverTrue(probes);
    bool cpu = false;
    for (const auto& s : probes) {
        if (s.runtime_id == "synthetic-cpu-fixture") {
            cpu = true;
            BOOST_CHECK(s.present);
            BOOST_CHECK(!s.stub);
            BOOST_CHECK_EQUAL(s.backend, "CPU");
        }
    }
    BOOST_REQUIRE(cpu);

    modelnet::ReadyReceipt rec;
    std::string code, err;
    BOOST_REQUIRE(modelnet::LoadTrustedRuntime("synthetic-cpu-fixture", TinyVerified(), CpuParams(), rec, code, err));
    BOOST_CHECK(code.empty());
    BOOST_CHECK(rec.smoke_performed);
    BOOST_CHECK(rec.smoke_passed);
    BOOST_CHECK(rec.achieved == modelnet::ReadinessTarget::FIRST_USEFUL_RESULT);
    BOOST_CHECK(!rec.lease_id.empty());
    BOOST_CHECK(rec.json.exists("remote_endpoint") && rec.json["remote_endpoint"].isFalse());
    BOOST_CHECK(rec.json.exists("funded_wallet") && rec.json["funded_wallet"].isFalse());
    BOOST_CHECK_EQUAL(rec.json["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK(rec.json.exists("stub") && rec.json["stub"].isFalse());

    modelnet::Digest48 expected{};
    std::string serr;
    BOOST_REQUIRE(modelnet::CpuFixtureSmoke(TinyVerified(), expected, serr));
    BOOST_CHECK_EQUAL(rec.json["smoke_digest48"].get_str(), expected.Hex());
}

BOOST_AUTO_TEST_CASE(JIT_RUN_02)
{
    AssertAccelCase("JIT-RUN-02", "CUDA", "llama.cpp", "CUDA");
}

BOOST_AUTO_TEST_CASE(JIT_RUN_03)
{
    AssertAccelCase("JIT-RUN-03", "ROCM", "vLLM", "ROCM");
}

BOOST_AUTO_TEST_CASE(JIT_RUN_04)
{
    AssertAccelCase("JIT-RUN-04", "METAL", "MLX", "METAL");
}

BOOST_AUTO_TEST_CASE(JIT_RUN_05)
{
    BOOST_TEST_MESSAGE("JIT-RUN-05 unknown adapter parameters");
    AssertUnknownParamsRejected("synthetic-cpu-fixture");
    AssertUnknownParamsRejected("llama.cpp");

    UniValue pkg(UniValue::VOBJ);
    pkg.pushKV("executable_path", "/usr/bin/true");
    pkg.pushKV("adapter_abi", modelnet::RUNTIME_ADAPTER_ABI);
    modelnet::ReadyReceipt rec;
    std::string code, err;
    BOOST_CHECK(!modelnet::LoadTrustedRuntime("llama.cpp", TinyVerified(), pkg, rec, code, err));
    BOOST_CHECK_EQUAL(code, "UNKNOWN_ADAPTER_PARAMETER");
}

BOOST_AUTO_TEST_CASE(JIT_RUN_06)
{
    BOOST_TEST_MESSAGE("JIT-RUN-06 sleep discarded state");
    modelnet::ReadyReceipt loaded;
    std::string code, err;
    BOOST_REQUIRE(modelnet::LoadTrustedRuntime("synthetic-cpu-fixture", TinyVerified(), CpuParams(), loaded, code, err));
    BOOST_REQUIRE(loaded.smoke_passed);

    UniValue sleep_st;
    BOOST_REQUIRE(modelnet::SleepRuntimePreserveWeights(loaded.lease_id, sleep_st, code, err));
    BOOST_CHECK(sleep_st["weights_preserved"].isTrue());
    BOOST_CHECK(sleep_st["kv_discarded"].isTrue());
    BOOST_CHECK(sleep_st["workspace_discarded"].isTrue());
    BOOST_CHECK(sleep_st["ready"].isFalse());
    BOOST_CHECK(sleep_st["remap_only"].isFalse());

    modelnet::ReadyReceipt remapped;
    BOOST_CHECK(!modelnet::WakeRuntimeRemapOnly(loaded.lease_id, remapped, code, err));
    BOOST_CHECK_EQUAL(code, "PREMATURE_READY");
    BOOST_CHECK(!remapped.smoke_passed);
    BOOST_CHECK(remapped.json["remap_only"].isTrue());
    BOOST_CHECK(remapped.json["kv_rebuilt"].isFalse());
    BOOST_CHECK(remapped.json["ready"].isFalse());

    modelnet::ReadyReceipt woke;
    code.clear();
    err.clear();
    BOOST_REQUIRE(modelnet::WakeRuntimeRebuildKv(loaded.lease_id, woke, code, err));
    BOOST_CHECK(woke.smoke_passed);
    BOOST_CHECK(woke.achieved == modelnet::ReadinessTarget::FIRST_USEFUL_RESULT);
    BOOST_CHECK(woke.json["kv_rebuilt"].isTrue());
    BOOST_CHECK(woke.json["remap_only"].isFalse());
    BOOST_CHECK(woke.json["ready"].isTrue());
    BOOST_CHECK(woke.json["weights_preserved"].isTrue());
}

BOOST_AUTO_TEST_CASE(JIT_RUN_07)
{
    BOOST_TEST_MESSAGE("JIT-RUN-07 plugin ABI mismatch");
    std::string supported, code, err;
    BOOST_CHECK(modelnet::ProbeRuntimeAdapterAbi(modelnet::RUNTIME_ADAPTER_ABI, supported, code, err));
    BOOST_CHECK(!modelnet::ProbeRuntimeAdapterAbi("btx-runtime/0", supported, code, err));
    BOOST_CHECK_EQUAL(code, "ADAPTER_ABI_MISMATCH");
    BOOST_CHECK(supported.find(modelnet::RUNTIME_ADAPTER_ABI) != std::string::npos);
    BOOST_CHECK(supported.find("synthetic-cpu-fixture") != std::string::npos);

    UniValue bad(UniValue::VOBJ);
    bad.pushKV("adapter_abi", "other-abi");
    modelnet::ReadyReceipt rec;
    code.clear();
    err.clear();
    BOOST_CHECK(!modelnet::LoadTrustedRuntime("synthetic-cpu-fixture", TinyVerified(), bad, rec, code, err));
    BOOST_CHECK_EQUAL(code, "ADAPTER_ABI_MISMATCH");
    BOOST_CHECK(!rec.smoke_passed);
    BOOST_CHECK(err.find(modelnet::RUNTIME_ADAPTER_ABI) != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
