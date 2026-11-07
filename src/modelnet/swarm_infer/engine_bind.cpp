// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/engine_bind.h>

#include <modelnet/swarm_engine.h>
#include <modelnet/swarm_infer/codes.h>

#include <string>

namespace modelnet {

SwarmInferBinding SwarmInferProbeAndQualify(const std::string& name, const fs::path& binary, std::string& err)
{
    SwarmInferBinding binding;
    const SwarmEngineStatus probed = SwarmProbeEngine(name, binary, err);
    if (probed.code == SwarmInferCode::engine) {
        binding.stored = false;
        binding.code = SwarmInferCode::engine;
        err = SwarmInferCode::engine;
        return binding;
    }
    if (!probed.present || probed.code != SwarmInferCode::installed) {
        binding.stored = true;
        binding.name = probed.name;
        binding.binary = binary;
        binding.present = false;
        binding.qualified = false;
        binding.advertised = false;
        binding.status = SwarmInferCode::engine_absent;
        binding.code = SwarmInferCode::engine_absent;
        err = SwarmInferCode::engine_absent;
        return binding;
    }

    // The file is a regular file. Qualify it without supplying a measurement.
    // 0.0 is the unused argument, not a tok/s. SwarmQualifyEngine leaves
    // qualified and advertised false. This function does not spawn, and it
    // does not start vLLM, SGLang, or CUDA.
    SwarmEngineStatus qualified = probed;
    std::string qualify_err;
    const bool qualify_ok = SwarmQualifyEngine(qualified, false, 0.0, qualify_err);
    (void)qualify_ok;
    (void)qualify_err;
    binding.stored = true;
    binding.name = qualified.name;
    binding.binary = binary;
    binding.present = true;
    binding.qualified = false;
    binding.advertised = false;
    binding.status = SwarmInferCode::installed;
    binding.code = SwarmInferCode::unqualified;
    err = SwarmInferCode::unqualified;
    return binding;
}

} // namespace modelnet
