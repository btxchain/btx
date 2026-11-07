// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_OPEN_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_OPEN_H

#include <modelnet/swarm_adminhold/book.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Opens one channel.
 * An empty channel is CHANNEL and the book stays as it was.
 * refund_height below 1 is HEIGHT and the book stays as it was.
 * A sponsor_key size other than 1312 is KEY and the book stays as it was.
 * A second Open of the same channel is REPLAY and leaves the first
 * height and key. Those checks run in that order.
 */
class SwarmAdminHoldOpen {
public:
    bool Apply(SwarmAdminHoldBook& book,
               const std::string& channel,
               int64_t refund_height,
               const std::vector<unsigned char>& sponsor_key,
               std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_OPEN_H
