// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SCHEDWITNESS_STAY_H
#define BITCOIN_MODELNET_SWARM_SCHEDWITNESS_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored witness stays unsigned.
 * refusal() is NOT_SIGNED. signed_ok() stays false.
 * This type does not store a witness, does not arm a spend, and does not
 * attach a key.
 */
class SwarmSchedWitnessStay {
public:
    std::string refusal() const;
    bool signed_ok() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SCHEDWITNESS_STAY_H
