// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_INFER_RUNTIME_H
#define BTX_MODELNET_SWARM_INFER_RUNTIME_H

#include <string>

namespace modelnet {

/**
 * A request to start an inference runtime.
 * want_vllm, want_sglang, and want_cuda are caller wishes.
 * This control plane does not grant them.
 */
struct SwarmInferRuntimeRequest {
    bool want_vllm{false};
    bool want_sglang{false};
    bool want_cuda{false};
};

/**
 * Runtime decision. started and process_spawned stay false.
 * No process is created.
 */
struct SwarmInferRuntime {
    bool started{false};
    bool process_spawned{false};
};

/**
 * Record that vLLM, SGLang, and CUDA stay stopped.
 * The request flags are ignored. err is NOT_STARTED.
 * This function does not spawn a process.
 */
SwarmInferRuntime SwarmInferConsiderRuntime(const SwarmInferRuntimeRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_INFER_RUNTIME_H
