// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvplace/decision.h>

#include <modelnet/swarm_kvplace/codes.h>

#include <string>

namespace modelnet {

bool SwarmKvPlaceDecide(const std::string& winner, bool engine_present, std::string& err)
{
    if (winner == SWARM_KVPLACE_TRANSFER) {
        if (!engine_present) {
            err = SWARM_KVPLACE_ENGINE_ABSENT;
            return false;
        }
        err = SWARM_KVPLACE_LOCAL;
        return true;
    }
    err.clear();
    return true;
}

} // namespace modelnet
