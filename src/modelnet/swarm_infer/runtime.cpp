// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_infer/runtime.h>

#include <modelnet/swarm_infer/codes.h>

#include <string>

namespace modelnet {

SwarmInferRuntime SwarmInferConsiderRuntime(const SwarmInferRuntimeRequest& request, std::string& err)
{
    // Wishes to start vLLM, SGLang, or CUDA are not a launch.
    (void)request;
    SwarmInferRuntime runtime;
    runtime.started = false;
    runtime.process_spawned = false;
    err = SwarmInferCode::not_started;
    return runtime;
}

} // namespace modelnet
