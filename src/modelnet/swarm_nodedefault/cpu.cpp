// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/cpu.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

int SwarmNodeDefaultCpu::cpu_threads() const
{
    return m_threads;
}

bool SwarmNodeDefaultCpu::RaiseThreads(int n, std::string& err)
{
    if (n < 0 || n > kSwarmNodeDefaultCpuThreads) {
        err = kSwarmNodeDefaultCapped;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
