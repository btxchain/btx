// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_mixedhold/stay.h>

#include <modelnet/swarm_mixedhold/codes.h>
#include <modelnet/swarm_mixedhold/limits.h>

namespace modelnet {

std::string SwarmMixedHoldStay::refusal() const
{
    return std::string{kSwarmMixedHoldHeld};
}

bool SwarmMixedHoldStay::running() const
{
    return kSwarmMixedHoldRunning;
}

} // namespace modelnet
