// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/capability.h>

#include <crypto/sha384.h>
#include <util/fs.h>

#include <cstdlib>

namespace modelnet {

std::vector<RuntimeAdapterStatus> ProbeRuntimeAdapters()
{
    std::vector<RuntimeAdapterStatus> out;
    RuntimeAdapterStatus cpu;
    cpu.runtime_id = "synthetic-cpu-fixture";
    cpu.backend = "CPU";
    cpu.present = true;
    cpu.stub = false;
    cpu.detail = "deterministic SHA-384 smoke";
    out.push_back(cpu);

    auto probe_exe = [](const char* name, const char* runtime, const char* backend) {
        RuntimeAdapterStatus s;
        s.runtime_id = runtime;
        s.backend = backend;
        s.stub = false;
        if (const char* env = std::getenv(name)) {
            s.present = fs::exists(fs::PathFromString(env));
            s.detail = env;
        } else {
            s.present = false;
            s.detail = "not installed; adapter code present, hardware/runtime NOT_RUN until probe succeeds";
        }
        return s;
    };
    out.push_back(probe_exe("BTX_LLAMA_CLI", "llama.cpp", "CPU/CUDA/HIP/Metal"));
    out.push_back(probe_exe("BTX_VLLM", "vLLM", "CUDA/ROCm"));
    out.push_back(probe_exe("BTX_MLX", "MLX", "Metal"));
    return out;
}

bool CpuFixtureSmoke(Span<const unsigned char> verified, Digest48& out_digest, std::string& err)
{
    if (verified.empty()) {
        err = "empty verified payload";
        return false;
    }
    CSHA384 hasher;
    hasher.Write(verified.data(), verified.size());
    hasher.Finalize(out_digest.data.data());
    return true;
}

} // namespace modelnet
