// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cpucap.h>

#include <cstdint>

namespace modelnet {

static constexpr int64_t kSwarmCpuCapThreads = 64;

SwarmCpuCapResult SwarmNoteCpuCap(const SwarmCpuCap& cap, std::string& err)
{
    SwarmCpuCapResult result;
    result.threads_used = 0;
    result.launched = false;
    if (cap.node_id.empty() || cap.requested_threads < 1) {
        result.threads_used = 0;
        result.launched = false;
        result.code = "CPU";
        err = "CPU";
        return result;
    }
    // Extra threads above the cap of 64 are not used. This wins even
    // when want_launch is true. Nothing is started.
    if (cap.requested_threads > kSwarmCpuCapThreads) {
        result.threads_used = kSwarmCpuCapThreads;
        result.launched = false;
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    // This note does not launch threads.
    if (cap.want_launch) {
        result.threads_used = cap.requested_threads;
        result.launched = false;
        result.code = "HELD";
        err.clear();
        return result;
    }
    result.threads_used = cap.requested_threads;
    result.launched = false;
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
