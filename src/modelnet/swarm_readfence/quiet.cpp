// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/quiet.h>

#include <modelnet/swarm_readfence/limits.h>

namespace modelnet {

int64_t SwarmReadQuiet::bytes_moved() const
{
    return kSwarmReadBytesMoved;
}

bool SwarmReadQuiet::qualified() const
{
    return kSwarmReadQualified;
}

bool SwarmReadQuiet::advertised() const
{
    return kSwarmReadAdvertised;
}

bool SwarmReadQuiet::process_started() const
{
    return kSwarmReadProcessStarted;
}

bool SwarmReadQuiet::cuda_buffer() const
{
    return kSwarmReadCudaBuffer;
}

} // namespace modelnet
