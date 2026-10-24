// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROF_STAY_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROF_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored name stays unrenamed.
 * refusal() is HELD. renamed() stays false.
 * This type does not store a name and does not move bytes.
 * It does not change the profile string.
 */
class SwarmLaunchProfileStay {
public:
    std::string refusal() const;
    bool renamed() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROF_STAY_H
