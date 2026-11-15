// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_dedup/quiet.h>

#include <modelnet/swarm_dedup/limits.h>

#include <cstdint>

namespace modelnet {

std::int64_t SwarmPieceDedupQuiet::bytes_moved() const
{
    return kSwarmPieceDedupBytesMoved;
}

bool SwarmPieceDedupQuiet::launched() const
{
    return kSwarmPieceDedupLaunched;
}

bool SwarmPieceDedupQuiet::gpu() const
{
    return kSwarmPieceDedupGpu;
}

} // namespace modelnet
