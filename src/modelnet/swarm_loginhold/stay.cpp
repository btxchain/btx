// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_loginhold/stay.h>

#include <modelnet/swarm_loginhold/codes.h>
#include <modelnet/swarm_loginhold/limits.h>

namespace modelnet {

std::string SwarmLoginHoldStay::refusal() const
{
    return std::string{kSwarmLoginHoldHeld};
}

bool SwarmLoginHoldStay::logged_in() const
{
    return kSwarmLoginHoldLoggedIn;
}

} // namespace modelnet
