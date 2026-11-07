// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_cachepair/quiet.h>

#include <modelnet/swarm_cachepair/limits.h>

namespace modelnet {

int64_t SwarmCachePairQuiet::bytes_moved() const
{
    return kSwarmCachePairBytesMoved;
}

bool SwarmCachePairQuiet::cuda_buffer() const
{
    return kSwarmCachePairCudaBuffer;
}

bool SwarmCachePairQuiet::launched() const
{
    return kSwarmCachePairLaunched;
}

} // namespace modelnet
