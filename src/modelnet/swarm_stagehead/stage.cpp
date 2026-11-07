// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stagehead/stage.h>

#include <modelnet/swarm_stagehead/codes.h>

namespace modelnet {

bool SwarmStagePlace::Place(SwarmStageCandidate& slot, const std::string& candidate, std::string& err) const
{
    if (candidate.empty() || !slot.replace(candidate)) {
        err = kSwarmStageHead;
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
