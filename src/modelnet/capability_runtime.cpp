// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Trusted local runtime adapters (BTX-SPEC-0348-CAPABILITY-01 RUN).
// Operator-env executables only: BTX_LLAMA_CLI / BTX_VLLM / BTX_MLX.
// Package JSON never chooses process authority. CUDA/ROCm/Metal PASS is
// not claimed from a mock or from nvidia-smi/rocm/Metal absence.
//
// Exported symbols (coordinator may declare these in capability.h):
//   LoadTrustedRuntime
//   SleepRuntimePreserveWeights
//   WakeRuntimeRebuildKv
//   WakeRuntimeRemapOnly
//   ProbeAcceleratedAdapters
//   ProbeRuntimeAdapterAbi
// ProbeRuntimeAdapters / CpuFixtureSmoke remain in capability_exec.cpp.

#include <modelnet/capability.h>

#include <crypto/sha384.h>
#include <util/fs.h>

#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace modelnet {
namespace {

struct RuntimeSession {
    std::string runtime_id;
    std::string lease_id;
    std::string backend;
    std::vector<unsigned char> weights;
    Digest48 weight_digest{};
    Digest48 kv_digest{};
    bool weights_resident{true};
    bool kv_resident{true};
    bool kv_rebuilt{true};
    bool remapped_only{false};
    bool sleeping{false};
    bool ready{false};
};

std::mutex g_rt_mu;
std::map<std::string, RuntimeSession> g_sessions;

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

bool FailReceipt(ReadyReceipt& receipt, std::string& err_code, std::string& err, const char* code,
                 const std::string& msg)
{
    receipt.smoke_passed = false;
    receipt.smoke_performed = false;
    return Fail(err_code, err, code, msg);
}

std::string Lower(std::string s)
{
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

std::string NormKey(std::string s)
{
    s = Lower(std::move(s));
    for (char& c : s) {
        if (c == '-') c = '_';
    }
    return s;
}

bool CommandOutputContains(const char* cmd, const char* needle)
{
    FILE* fp = popen(cmd, "r");
    if (!fp) return false;
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), fp) != nullptr) out += buf;
    const int rc = pclose(fp);
    if (rc != 0) return false;
    if (needle == nullptr || needle[0] == '\0') return !out.empty();
    return out.find(needle) != std::string::npos;
}

bool HardcodedExeProbe(const char* path, const char* args, const char* needle)
{
    if (!fs::exists(fs::PathFromString(path))) return false;
    std::string cmd = std::string(path);
    cmd += ' ';
    cmd += args;
    cmd += " 2>/dev/null";
    return CommandOutputContains(cmd.c_str(), needle);
}

RuntimeAdapterStatus MakeAccelStatus(const char* id, const char* backend, bool present, const std::string& detail)
{
    RuntimeAdapterStatus s;
    s.runtime_id = id;
    s.backend = backend;
    s.present = present;
    s.stub = false;
    s.detail = present ? detail : (detail.find("NOT_RUN") != std::string::npos ? detail : std::string("NOT_RUN"));
    return s;
}

bool CudaUsable(std::string& detail)
{
    static const char* const kSmi[] = {"/usr/bin/nvidia-smi", "/usr/local/bin/nvidia-smi"};
    for (const char* p : kSmi) {
        if (HardcodedExeProbe(p, "-L", "GPU")) {
            detail = std::string(p) + " -L usable";
            return true;
        }
    }
    if (CommandOutputContains("nvidia-smi -L 2>/dev/null", "GPU")) {
        detail = "nvidia-smi -L usable";
        return true;
    }
    detail = "nvidia-smi not actually usable; NOT_RUN";
    return false;
}

bool RocmUsable(std::string& detail)
{
    static const char* const kInfo[] = {
        "/opt/rocm/bin/rocminfo", "/usr/bin/rocminfo", "/usr/bin/rocm-smi", "/opt/rocm/bin/rocm-smi",
    };
    for (const char* p : kInfo) {
        const char* needle = std::strstr(p, "rocm-smi") ? "GPU" : "HSA";
        const char* args = std::strstr(p, "rocm-smi") ? "-i" : "";
        if (HardcodedExeProbe(p, args, needle) || HardcodedExeProbe(p, args, "gfx") ||
            HardcodedExeProbe(p, args, "Gfx")) {
            detail = std::string(p) + " usable";
            return true;
        }
    }
    detail = "rocminfo/rocm-smi not actually usable; NOT_RUN";
    return false;
}

bool MetalUsable(std::string& detail)
{
#ifdef __APPLE__
    // Framework presence is not device usability. Without a real Metal evaluation
    // this translation unit must not advertise PASS or present=true.
    (void)fs::exists(fs::PathFromString("/System/Library/Frameworks/Metal.framework"));
    detail = "Metal device evaluation not executed in this adapter; NOT_RUN";
    return false;
#else
    detail = "Metal/MLX not actually usable on this platform; NOT_RUN";
    return false;
#endif
}

const std::set<std::string> kAllowedParamKeys{
    "adapter_abi", "backend",     "runtime_id",      "context_tokens", "threads", "gpu_layers",
    "device_arch", "driver_abi", "layout_digest48", "geometry",       "smoke",   "flags",
};

const std::set<std::string> kForbiddenParamKeys{
    "executable_path", "executable", "argv",     "extra_argv", "command",  "cmd",      "shell",
    "env",             "ld_preload", "preload",  "plugin",     "plugins",  "so_path",  "rpath",
    "url",             "endpoint",   "remote",   "api_base",   "wallet",   "spend",    "hf_token",
    "api_key",         "trust_remote_code", "package", "package_json", "so",
};

const std::set<std::string> kAllowedFlagKeys{
    "m",
    "model",
    "model_path",
    "c",
    "ctx_size",
    "context_size",
    "context",
    "context_tokens",
    "ngl",
    "n_gpu_layers",
    "gpu_layers",
    "t",
    "threads",
};

bool KeyForbidden(const std::string& nk)
{
    return kForbiddenParamKeys.count(nk) != 0;
}

bool ValidateTypedParams(const UniValue& params, std::string& err_code, std::string& err)
{
    if (params.isNull()) return true;
    if (!params.isObject()) return Fail(err_code, err, "NONCANONICAL_PAYLOAD", "typed_params");
    for (const auto& k : params.getKeys()) {
        const std::string nk = NormKey(k);
        if (KeyForbidden(nk) || nk == "ldpreload") {
            return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", k);
        }
        if (kAllowedParamKeys.count(nk) == 0) {
            return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", k);
        }
        if (nk == "flags") {
            const UniValue& flags = params[k];
            if (!flags.isObject()) {
                return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", "flags");
            }
            for (const auto& fk : flags.getKeys()) {
                const std::string nfk = NormKey(fk);
                if (KeyForbidden(nfk) || kAllowedFlagKeys.count(nfk) == 0) {
                    return Fail(err_code, err, "UNKNOWN_ADAPTER_PARAMETER", fk);
                }
            }
        }
    }
    return true;
}

std::string ParamStr(const UniValue& params, const char* key)
{
    if (!params.isObject() || !params.exists(key) || !params[key].isStr()) return {};
    return params[key].get_str();
}

const char* OperatorEnvName(const std::string& runtime_id)
{
    if (runtime_id == "llama.cpp") return "BTX_LLAMA_CLI";
    if (runtime_id == "vLLM" || runtime_id == "vllm") return "BTX_VLLM";
    if (runtime_id == "MLX" || runtime_id == "mlx") return "BTX_MLX";
    return nullptr;
}

std::string CanonicalRuntimeId(const std::string& runtime_id)
{
    if (runtime_id == "vllm") return "vLLM";
    if (runtime_id == "mlx") return "MLX";
    return runtime_id;
}

std::string DefaultBackend(const std::string& runtime_id)
{
    if (runtime_id == "synthetic-cpu-fixture") return "CPU";
    if (runtime_id == "llama.cpp") return "CPU";
    if (runtime_id == "vLLM") return "CUDA";
    if (runtime_id == "MLX") return "METAL";
    return {};
}

std::string CanonicalBackend(std::string b)
{
    b = Lower(std::move(b));
    if (b == "cpu") return "CPU";
    if (b == "cuda") return "CUDA";
    if (b == "rocm" || b == "hip") return "ROCM";
    if (b == "metal" || b == "mlx") return "METAL";
    return {};
}

bool BackendNeedsCuda(const std::string& backend) { return backend == "CUDA"; }
bool BackendNeedsRocm(const std::string& backend) { return backend == "ROCM"; }
bool BackendNeedsMetal(const std::string& backend) { return backend == "METAL"; }

void FillReadyJson(ReadyReceipt& receipt, const RuntimeSession& sess, const Digest48& smoke)
{
    receipt.json = UniValue(UniValue::VOBJ);
    receipt.json.pushKV("lease_id", sess.lease_id);
    receipt.json.pushKV("runtime_id", sess.runtime_id);
    receipt.json.pushKV("adapter_abi", RUNTIME_ADAPTER_ABI);
    receipt.json.pushKV("backend", sess.backend);
    receipt.json.pushKV("stub", false);
    receipt.json.pushKV("achieved", ReadinessTargetName(receipt.achieved));
    receipt.json.pushKV("smoke_performed", receipt.smoke_performed);
    receipt.json.pushKV("smoke_passed", receipt.smoke_passed);
    receipt.json.pushKV("smoke_digest48", smoke.Hex());
    receipt.json.pushKV("weights_preserved", sess.weights_resident);
    receipt.json.pushKV("kv_resident", sess.kv_resident);
    receipt.json.pushKV("kv_rebuilt", sess.kv_rebuilt);
    receipt.json.pushKV("remap_only", sess.remapped_only);
    receipt.json.pushKV("ready", sess.ready);
    receipt.json.pushKV("remote_endpoint", false);
    receipt.json.pushKV("funded_wallet", false);
    receipt.json.pushKV("automatic_spend_atoms", 0);
}

Digest48 RebuildKvDigest(const std::vector<unsigned char>& weights)
{
    Digest48 out{};
    CSHA384 hasher;
    hasher.Write(weights.data(), weights.size());
    static const unsigned char tag[] = {'K', 'V', '_', 'R', 'E', 'B', 'U', 'I', 'L', 'D'};
    hasher.Write(tag, sizeof(tag));
    hasher.Finalize(out.data.data());
    return out;
}

} // namespace

std::vector<RuntimeAdapterStatus> ProbeAcceleratedAdapters()
{
    std::vector<RuntimeAdapterStatus> out;
    std::string d;
    const bool cuda = CudaUsable(d);
    out.push_back(MakeAccelStatus("cuda", "CUDA", cuda, d));
    d.clear();
    const bool rocm = RocmUsable(d);
    out.push_back(MakeAccelStatus("rocm", "ROCM", rocm, d));
    d.clear();
    const bool metal = MetalUsable(d);
    out.push_back(MakeAccelStatus("mlx", "METAL", metal, d));
    for (auto& s : out) s.stub = false;
    return out;
}

bool ProbeRuntimeAdapterAbi(const std::string& candidate_abi, std::string& supported_path, std::string& err_code,
                            std::string& err)
{
    supported_path = std::string("adapter_abi=") + RUNTIME_ADAPTER_ABI +
                     "; supported path=synthetic-cpu-fixture or operator env BTX_LLAMA_CLI/BTX_VLLM/BTX_MLX";
    if (candidate_abi.empty() || candidate_abi == RUNTIME_ADAPTER_ABI) return true;
    return Fail(err_code, err, "ADAPTER_ABI_MISMATCH",
                std::string("incompatible adapter ABI ") + candidate_abi + "; use " + supported_path);
}

bool LoadTrustedRuntime(const std::string& runtime_id, Span<const unsigned char> verified,
                        const UniValue& typed_params, ReadyReceipt& receipt, std::string& err_code, std::string& err)
{
    receipt = {};
    err_code.clear();
    err.clear();
    if (!ValidateTypedParams(typed_params, err_code, err)) {
        receipt.smoke_passed = false;
        receipt.smoke_performed = false;
        return false;
    }

    const std::string abi = ParamStr(typed_params, "adapter_abi");
    std::string supported;
    if (!ProbeRuntimeAdapterAbi(abi, supported, err_code, err)) {
        receipt.smoke_passed = false;
        receipt.smoke_performed = false;
        return false;
    }

    const std::string rid = CanonicalRuntimeId(runtime_id);
    if (rid != "synthetic-cpu-fixture" && rid != "llama.cpp" && rid != "vLLM" && rid != "MLX") {
        return FailReceipt(receipt, err_code, err, "UNSUPPORTED_RUNTIME_PROFILE", runtime_id);
    }

    std::string backend;
    const std::string backend_in = ParamStr(typed_params, "backend");
    if (backend_in.empty()) {
        backend = DefaultBackend(rid);
    } else {
        backend = CanonicalBackend(backend_in);
        if (backend.empty()) {
            return FailReceipt(receipt, err_code, err, "UNKNOWN_ADAPTER_PARAMETER", backend_in);
        }
    }

    if (rid == "synthetic-cpu-fixture" && backend != "CPU") {
        return FailReceipt(receipt, err_code, err, "UNSUPPORTED_RUNTIME_PROFILE",
                           "synthetic-cpu-fixture is CPU-only");
    }

    if (rid != "synthetic-cpu-fixture") {
        const char* env_name = OperatorEnvName(rid);
        const char* env = env_name ? std::getenv(env_name) : nullptr;
        if (!env || env[0] == '\0') {
            return FailReceipt(receipt, err_code, err, "RUNTIME_NOT_INSTALLED",
                               std::string(env_name ? env_name : "runtime") +
                                   " unset; operator env required, package JSON cannot choose the executable; NOT_RUN");
        }
        if (!fs::exists(fs::PathFromString(env))) {
            return FailReceipt(receipt, err_code, err, "RUNTIME_NOT_INSTALLED",
                               std::string(env_name) + " path not present; NOT_RUN");
        }
    }

    if (BackendNeedsCuda(backend)) {
        std::string d;
        if (!CudaUsable(d)) {
            return FailReceipt(receipt, err_code, err, "HARDWARE_NOT_RUN", d);
        }
        return FailReceipt(receipt, err_code, err, "LIVE_RUNTIME_NOT_RUN",
                           "CUDA usable but live loader/warmup was not executed; mock is not PASS; NOT_RUN");
    }
    if (BackendNeedsRocm(backend)) {
        std::string d;
        if (!RocmUsable(d)) {
            return FailReceipt(receipt, err_code, err, "HARDWARE_NOT_RUN", d);
        }
        return FailReceipt(receipt, err_code, err, "LIVE_RUNTIME_NOT_RUN",
                           "ROCm usable but live HIP loader/sleep was not executed; mock is not PASS; NOT_RUN");
    }
    if (BackendNeedsMetal(backend)) {
        std::string d;
        if (!MetalUsable(d)) {
            return FailReceipt(receipt, err_code, err, "HARDWARE_NOT_RUN", d);
        }
        return FailReceipt(receipt, err_code, err, "LIVE_RUNTIME_NOT_RUN",
                           "Metal usable but MLX evaluation was not executed; mock is not PASS; NOT_RUN");
    }

    if (rid != "synthetic-cpu-fixture") {
        return FailReceipt(receipt, err_code, err, "LIVE_RUNTIME_NOT_RUN",
                           rid + " operator env resolved; live process was not spawned; NOT_RUN");
    }

    if (verified.empty()) {
        return FailReceipt(receipt, err_code, err, "UNVERIFIED_RANGE", "empty verified payload");
    }

    Digest48 smoke{};
    if (!CpuFixtureSmoke(verified, smoke, err)) {
        return FailReceipt(receipt, err_code, err, "UNVERIFIED_RANGE", err);
    }

    RuntimeSession sess;
    sess.runtime_id = rid;
    sess.backend = "CPU";
    sess.lease_id = GenerationHex(NewGeneration());
    sess.weights.assign(verified.begin(), verified.end());
    sess.weight_digest = smoke;
    sess.kv_digest = RebuildKvDigest(sess.weights);
    sess.weights_resident = true;
    sess.kv_resident = true;
    sess.kv_rebuilt = true;
    sess.remapped_only = false;
    sess.sleeping = false;
    sess.ready = true;

    receipt.lease_id = sess.lease_id;
    receipt.achieved = ReadinessTarget::FIRST_USEFUL_RESULT;
    receipt.smoke_performed = true;
    receipt.smoke_passed = true;
    FillReadyJson(receipt, sess, smoke);

    std::lock_guard<std::mutex> lock(g_rt_mu);
    g_sessions[sess.lease_id] = std::move(sess);
    return true;
}

bool SleepRuntimePreserveWeights(const std::string& lease_id, UniValue& status, std::string& err_code, std::string& err)
{
    status = UniValue(UniValue::VOBJ);
    std::lock_guard<std::mutex> lock(g_rt_mu);
    auto it = g_sessions.find(lease_id);
    if (it == g_sessions.end()) return Fail(err_code, err, "UNKNOWN_LEASE", lease_id);
    RuntimeSession& s = it->second;
    if (s.weights.empty() || !s.weights_resident) {
        return Fail(err_code, err, "UNVERIFIED_RANGE", "weights missing; cannot sleep");
    }
    s.kv_resident = false;
    s.kv_rebuilt = false;
    s.kv_digest = {};
    s.remapped_only = false;
    s.sleeping = true;
    s.ready = false;
    status.pushKV("lease_id", s.lease_id);
    status.pushKV("runtime_id", s.runtime_id);
    status.pushKV("weights_preserved", true);
    status.pushKV("kv_discarded", true);
    status.pushKV("workspace_discarded", true);
    status.pushKV("ready", false);
    status.pushKV("remap_only", false);
    status.pushKV("premature_ready", false);
    status.pushKV("automatic_spend_atoms", 0);
    return true;
}

bool WakeRuntimeRemapOnly(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err)
{
    receipt = {};
    std::lock_guard<std::mutex> lock(g_rt_mu);
    auto it = g_sessions.find(lease_id);
    if (it == g_sessions.end()) return Fail(err_code, err, "UNKNOWN_LEASE", lease_id);
    RuntimeSession& s = it->second;
    s.remapped_only = true;
    s.kv_rebuilt = false;
    s.kv_resident = false;
    s.ready = false;
    receipt.lease_id = s.lease_id;
    receipt.achieved = ReadinessTarget::RUNTIME_LOADED;
    receipt.smoke_performed = false;
    receipt.smoke_passed = false;
    FillReadyJson(receipt, s, s.weight_digest);
    return Fail(err_code, err, "PREMATURE_READY",
                "remapping discarded KV/workspace pages is not readiness");
}

bool WakeRuntimeRebuildKv(const std::string& lease_id, ReadyReceipt& receipt, std::string& err_code, std::string& err)
{
    receipt = {};
    std::lock_guard<std::mutex> lock(g_rt_mu);
    auto it = g_sessions.find(lease_id);
    if (it == g_sessions.end()) return Fail(err_code, err, "UNKNOWN_LEASE", lease_id);
    RuntimeSession& s = it->second;
    if (!s.weights_resident || s.weights.empty()) {
        return FailReceipt(receipt, err_code, err, "UNVERIFIED_RANGE", "preserved weights missing");
    }
    if (s.remapped_only && !s.kv_rebuilt) {
        // Remap may have happened; it is not success. Rebuild is mandatory.
    }
    Digest48 smoke{};
    std::string serr;
    if (!CpuFixtureSmoke(Span<const unsigned char>{s.weights.data(), s.weights.size()}, smoke, serr)) {
        return FailReceipt(receipt, err_code, err, "UNVERIFIED_RANGE", serr);
    }
    s.kv_digest = RebuildKvDigest(s.weights);
    s.kv_resident = true;
    s.kv_rebuilt = true;
    s.remapped_only = false;
    s.sleeping = false;
    s.ready = true;
    s.weight_digest = smoke;
    receipt.lease_id = s.lease_id;
    receipt.achieved = ReadinessTarget::FIRST_USEFUL_RESULT;
    receipt.smoke_performed = true;
    receipt.smoke_passed = true;
    FillReadyJson(receipt, s, smoke);
    return true;
}

} // namespace modelnet
