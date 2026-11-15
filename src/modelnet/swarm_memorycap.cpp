// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_memorycap.h>

namespace modelnet {

static constexpr int64_t kSwarmMemoryCapMib = 16384;

SwarmMemoryCapResult SwarmCapMemory(const SwarmMemoryCap& cap, std::string& err)
{
    // Without a device file VRAM stays zero. A request above 16384 MiB stays capped and nothing is allocated.
    SwarmMemoryCapResult result;
    result.raised = false;
    result.memory_mib = 0;
    if (cap.node_id.empty()) {
        result.code = "NODE";
        result.raised = false;
        result.memory_mib = 0;
        err = "NODE";
        return result;
    }
    if (cap.no_device) {
        result.code = "VRAM_ZERO";
        result.raised = false;
        result.memory_mib = 0;
        err = "VRAM_ZERO";
        return result;
    }
    if (cap.requested_mib < 0 || cap.requested_mib > kSwarmMemoryCapMib) {
        result.code = "CAPPED";
        result.raised = false;
        result.memory_mib = cap.requested_mib > kSwarmMemoryCapMib ? kSwarmMemoryCapMib : 0;
        err = "CAPPED";
        return result;
    }
    if (cap.want_raise) {
        result.code = "HELD";
        result.raised = false;
        result.memory_mib = cap.requested_mib;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.raised = false;
    result.memory_mib = cap.requested_mib;
    err.clear();
    return result;
}

} // namespace modelnet
