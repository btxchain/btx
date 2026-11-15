// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/stay.h>

#include <modelnet/swarm_fsdphold/codes.h>
#include <modelnet/swarm_fsdphold/limits.h>

namespace modelnet {

std::string SwarmFsdpHoldStay::refusal() const
{
    return std::string{kSwarmFsdpHoldHeld};
}

bool SwarmFsdpHoldStay::running() const
{
    return kSwarmFsdpHoldRunning;
}

} // namespace modelnet
