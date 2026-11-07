// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEHEIGHT_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEHEIGHT_H

#include <modelnet/swarm_adminhold/book.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refuses a move of the refund height.
 * An unknown channel is CHANNEL. A stored channel is HELD.
 * next_height is discarded. The stored height stays.
 */
class SwarmAdminHoldMoveHeight {
public:
    bool Apply(const SwarmAdminHoldBook& book,
               const std::string& channel,
               int64_t next_height,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_MOVEHEIGHT_H
