// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/hold.h>

#include <modelnet/swarm_natpub/codes.h>
#include <modelnet/swarm_natpub/limits.h>

namespace modelnet {

std::string SwarmNatPubHold::code() const
{
    return std::string{kSwarmNatPubHeld};
}

bool SwarmNatPubHold::published() const
{
    return kSwarmNatPubPublished;
}

} // namespace modelnet
