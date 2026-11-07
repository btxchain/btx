// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_GUESTHOLD_NAME_H
#define BITCOIN_MODELNET_SWARM_GUESTHOLD_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a guest-agent name as the recorded name.
 * The characters are kept as written. No payload bytes are copied.
 * An empty name copies nothing.
 */
class SwarmGuestHoldName {
public:
    std::string copy(const std::string& name) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_GUESTHOLD_NAME_H
