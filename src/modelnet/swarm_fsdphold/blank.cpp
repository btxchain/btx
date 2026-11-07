// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fsdphold/blank.h>

#include <modelnet/swarm_fsdphold/codes.h>

namespace modelnet {

bool SwarmFsdpHoldBlank::accept(const std::string& name, std::string& err) const
{
    if (name.empty()) {
        err = kSwarmFsdpHoldFsdp;
        return false;
    }
    return true;
}

} // namespace modelnet
