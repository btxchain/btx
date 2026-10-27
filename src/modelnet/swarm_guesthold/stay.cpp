// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_guesthold/stay.h>

#include <modelnet/swarm_guesthold/codes.h>
#include <modelnet/swarm_guesthold/limits.h>

namespace modelnet {

std::string SwarmGuestHoldStay::refusal() const
{
    return std::string{kSwarmGuestHoldNotPassed};
}

bool SwarmGuestHoldStay::passed() const
{
    return kSwarmGuestHoldPassed;
}

bool SwarmGuestHoldStay::logged_in() const
{
    return kSwarmGuestHoldLoggedIn;
}

} // namespace modelnet
