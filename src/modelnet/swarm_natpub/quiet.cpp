// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/quiet.h>

#include <modelnet/swarm_natpub/limits.h>

namespace modelnet {

int64_t SwarmNatPubQuiet::bytes_moved() const
{
    return kSwarmNatPubBytesMoved;
}

bool SwarmNatPubQuiet::launched() const
{
    return kSwarmNatPubLaunched;
}

} // namespace modelnet
