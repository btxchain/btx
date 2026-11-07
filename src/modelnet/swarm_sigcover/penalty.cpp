// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/penalty.h>

#include <modelnet/swarm_sigcover/codes.h>

#include <string>

namespace modelnet {

bool SwarmSigCoverRefusePenalty(const std::string& id, std::string& err)
{
    // A known id and an unknown id both refuse. No penalty row is created.
    static_cast<void>(id.size());
    err = SWARM_SIGCOVER_NOT_PENALTY;
    return false;
}

} // namespace modelnet
