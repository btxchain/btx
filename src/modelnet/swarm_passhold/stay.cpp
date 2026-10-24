// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/stay.h>

#include <modelnet/swarm_passhold/codes.h>
#include <modelnet/swarm_passhold/limits.h>

namespace modelnet {

std::string SwarmPassHoldStay::refusal() const
{
    return std::string{kSwarmPassHoldNotStarted};
}

bool SwarmPassHoldStay::started() const
{
    return kSwarmPassHoldStarted;
}

bool SwarmPassHoldStay::passed() const
{
    return kSwarmPassHoldPassed;
}

} // namespace modelnet
