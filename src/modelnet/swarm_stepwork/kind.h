// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_KIND_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_KIND_H

#include <string>

namespace modelnet {

/**
 * The public kind this plane stores.
 * SwarmExperience::Store accepts public_trajectory and synthetic_trajectory.
 * This plane writes only public_trajectory, and only after that kind is
 * accepted. A refused kind is cleared and nothing is stored.
 */
bool SwarmStepWorkPublicKind(std::string& kind, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_KIND_H
