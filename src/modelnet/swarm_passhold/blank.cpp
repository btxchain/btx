// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_passhold/blank.h>

#include <modelnet/swarm_passhold/codes.h>

namespace modelnet {

bool SwarmPassHoldBlank::accept(const std::string& name, std::string& err) const
{
    if (name.empty()) {
        err = kSwarmPassHoldPassthrough;
        return false;
    }
    return true;
}

} // namespace modelnet
