// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_stepwork/offer.h>

#include <modelnet/swarm_experience/experience.h>
#include <modelnet/swarm_stepwork/codes.h>

#include <string>

namespace modelnet {

bool SwarmStepWorkOffer(SwarmExperience& experience, const std::string& id, std::string& err)
{
    if (experience.reward(id) < 0) {
        err = kSwarmStepWorkWork;
        return false;
    }
    return experience.TrainFrom(id, err);
}

} // namespace modelnet
