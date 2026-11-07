// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nodedefault/vram.h>

#include <modelnet/swarm_nodedefault/codes.h>

namespace modelnet {

int64_t SwarmNodeDefaultVram::vram_mib() const
{
    return m_vram_mib;
}

bool SwarmNodeDefaultVram::ClaimVram(int64_t n, std::string& err)
{
    if (n != kSwarmNodeDefaultVramMib) {
        err = kSwarmNodeDefaultVramZero;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
