// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradhold/blank.h>

#include <modelnet/swarm_gradhold/codes.h>

namespace modelnet {

bool SwarmGradHoldBlank::accept(const std::string& update_id, std::string& err) const
{
    if (update_id.empty()) {
        err = kSwarmGradHoldUpdate;
        return false;
    }
    return true;
}

} // namespace modelnet
