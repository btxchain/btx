// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEKEY_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEKEY_H

#include <modelnet/swarm_adminhold/book.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Refuses a move of the sponsor refund key.
 * An unknown channel is CHANNEL. A stored channel is HELD.
 * next_key is discarded. The stored key stays.
 */
class SwarmAdminHoldMoveKey {
public:
    bool Apply(const SwarmAdminHoldBook& book,
               const std::string& channel,
               const std::vector<unsigned char>& next_key,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEKEY_H
