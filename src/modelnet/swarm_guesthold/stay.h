// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_STAY_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored check stays unpassed and logged out.
 * refusal() is NOT_PASSED. passed() stays false.
 * logged_in() stays false.
 * This type does not store a name and does not move bytes.
 */
class SwarmGuestHoldStay {
public:
    std::string refusal() const;
    bool passed() const;
    bool logged_in() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_STAY_H
