// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdrot/stay.h>

#include <modelnet/swarm_holdrot/codes.h>
#include <modelnet/swarm_holdrot/limits.h>

namespace modelnet {

std::string SwarmHoldoutRotateStay::refusal() const
{
    return std::string{kSwarmHoldoutRotateNotRotating};
}

bool SwarmHoldoutRotateStay::rotated() const
{
    return kSwarmHoldoutRotateRotated;
}

} // namespace modelnet
