// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_GATE_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_GATE_H

#include <modelnet/swarm_launchprof/book.h>

#include <string>

namespace modelnet {

/**
 * What Rename should do with name.
 * code is PROFILE, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not rename the profile.
 * This function does not modify the book.
 */
struct SwarmLaunchProfileDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Rename.
 * An empty name is PROFILE and is not stored.
 * A name already stored is REPLAY. The first name stays.
 * Any other name may be stored. The caller then returns HELD.
 * PROFILE is decided before REPLAY. REPLAY is decided before HELD.
 */
SwarmLaunchProfileDecision SwarmLaunchProfileDecide(const SwarmLaunchProfileBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_GATE_H
