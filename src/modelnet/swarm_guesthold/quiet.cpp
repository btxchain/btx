// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/quiet.h>

#include <modelnet/swarm_guesthold/limits.h>

namespace modelnet {

int64_t SwarmGuestHoldQuiet::bytes_moved() const
{
    return kSwarmGuestHoldBytesMoved;
}

bool SwarmGuestHoldQuiet::gpu() const
{
    return kSwarmGuestHoldGpu;
}

bool SwarmGuestHoldQuiet::launched() const
{
    return kSwarmGuestHoldLaunched;
}

} // namespace modelnet
