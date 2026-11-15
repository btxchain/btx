// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_rescap/stay.h>

#include <modelnet/swarm_rescap/codes.h>
#include <modelnet/swarm_rescap/limits.h>

#include <string>

namespace modelnet {

std::string SwarmResCapStay::refusal() const
{
    return std::string{kSwarmResCapCapped};
}

bool SwarmResCapStay::raised() const
{
    return kSwarmResCapRaised;
}

int64_t SwarmResCapStay::cap_threads() const
{
    return kSwarmResCapThreadCap;
}

} // namespace modelnet
