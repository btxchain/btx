// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/quiet.h>

#include <modelnet/swarm_privfam/limits.h>

namespace modelnet {

int64_t SwarmPrivFamQuiet::bytes_moved() const
{
    return kSwarmPrivFamBytesMoved;
}

bool SwarmPrivFamQuiet::launched() const
{
    return kSwarmPrivFamLaunched;
}

} // namespace modelnet
