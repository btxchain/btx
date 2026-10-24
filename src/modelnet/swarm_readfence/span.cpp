// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/span.h>

#include <modelnet/swarm_readfence/limits.h>

namespace modelnet {

bool SwarmReadSpan::Store(int64_t size)
{
    if (size <= 0 || size > kSwarmReadAcceptMax) return false;
    m_size = size;
    m_held = true;
    return true;
}

} // namespace modelnet
