// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ablatehold/stay.h>

#include <modelnet/swarm_ablatehold/codes.h>
#include <modelnet/swarm_ablatehold/limits.h>

namespace modelnet {

std::string SwarmAblateHoldStay::refusal() const
{
    return std::string{kSwarmAblateHoldHeld};
}

bool SwarmAblateHoldStay::published() const
{
    return kSwarmAblateHoldPublished;
}

} // namespace modelnet
