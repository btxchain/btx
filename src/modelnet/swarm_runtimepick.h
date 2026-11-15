// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RUNTIMEPICK_H
#define BTX_MODELNET_SWARM_RUNTIMEPICK_H

#include <string>

namespace modelnet {

struct SwarmRuntimePickRequest {
    std::string name;
    bool installed{false};
    bool measurement_taken{false};
};

struct SwarmRuntimePickResult {
    bool selected{false};
    bool advertised{false};
    bool qualified{false};
    std::string code;
};

/**
 * Selects a known local runtime. advertised and qualified stay false.
 * This function does not exec a binary and does not open a GPU. A caller
 * saying measurement_taken is not a hardware benchmark and must not
 * advertise the engine.
 *
 * Known names, compared case-sensitively: vllm, sglang, lmcache, mooncake,
 * nixl, rdma, torch.
 *
 * Order: an empty or unknown name is RUNTIME and selected stays false.
 * installed false is ENGINE_ABSENT and selected stays false. A known
 * installed engine with measurement_taken false is INSTALLED and selected.
 * That is a local candidate only, and err is cleared. Otherwise the result
 * is SELECTED, selected is true, and err is cleared.
 */
SwarmRuntimePickResult SwarmSelectRuntime(const SwarmRuntimePickRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RUNTIMEPICK_H
