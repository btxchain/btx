// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LOGINHOLD_STAY_H
#define BITCOIN_MODELNET_SWARM_LOGINHOLD_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored request stays logged out.
 * refusal() is HELD. logged_in() stays false.
 * This type does not store a name and does not move bytes.
 */
class SwarmLoginHoldStay {
public:
    std::string refusal() const;
    bool logged_in() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LOGINHOLD_STAY_H
