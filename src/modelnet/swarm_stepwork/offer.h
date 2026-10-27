// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_OFFER_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_OFFER_H

#include <modelnet/swarm_experience/experience.h>

#include <string>

namespace modelnet {

/**
 * Offer a stored id to training.
 * An unknown id, including one whose reward is -1, is WORK and does not
 * call TrainFrom. A stored id calls SwarmExperience::TrainFrom.
 * This records an offer. It does not run a GPU and does not take a step.
 */
bool SwarmStepWorkOffer(SwarmExperience& experience, const std::string& id, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_OFFER_H
