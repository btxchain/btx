// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_experience/offer.h>

#include <modelnet/swarm_experience/error.h>
#include <modelnet/swarm_experience/kind.h>

namespace modelnet {

bool MarkExperienceOffered(ExperienceRow& row, std::string& err)
{
    if (row.id.empty()) {
        err = kExperienceTrajectory;
        return false;
    }
    if (!ExperienceKindAllowed(row.kind, err)) {
        return false;
    }
    row.offered = true;
    err.clear();
    return true;
}

} // namespace modelnet
