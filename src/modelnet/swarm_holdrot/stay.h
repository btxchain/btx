// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_HOLDROT_STAY_H
#define BITCOIN_MODELNET_SWARM_HOLDROT_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored holdout stays not rotating.
 * refusal() is NOT_ROTATING. rotated() stays false.
 * This type does not store a holdout and does not move bytes.
 */
class SwarmHoldoutRotateStay {
public:
    std::string refusal() const;
    bool rotated() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_HOLDROT_STAY_H
