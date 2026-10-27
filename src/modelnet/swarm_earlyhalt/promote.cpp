// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/promote.h>

#include <modelnet/swarm_earlyhalt/codes.h>

namespace modelnet {

bool SwarmEarlyHaltPromote::Apply(const SwarmEarlyHaltMark& mark, const SwarmEarlyHaltScore& score, std::string& err) const
{
    if (mark.set()) {
        err = kSwarmEarlyHaltStopped;
        return false;
    }
    if (!score.held()) {
        err = kSwarmEarlyHaltStep;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
