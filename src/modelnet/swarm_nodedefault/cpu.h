// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_NODEDEFAULT_CPU_H
#define BITCOIN_MODELNET_SWARM_NODEDEFAULT_CPU_H

#include <modelnet/swarm_nodedefault/limits.h>

#include <string>

namespace modelnet {

/**
 * CPU thread count for the default node.
 * cpu_threads() is 64 from construction. RaiseThreads with n above 64
 * or below 0 is CAPPED and leaves 64. A request in 0..64 is accepted
 * and leaves 64. This does not spawn a process.
 */
class SwarmNodeDefaultCpu {
public:
    int cpu_threads() const;
    bool RaiseThreads(int n, std::string& err);

private:
    int m_threads{kSwarmNodeDefaultCpuThreads};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_NODEDEFAULT_CPU_H
