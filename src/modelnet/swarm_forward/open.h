// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FORWARD_OPEN_H
#define BITCOIN_MODELNET_SWARM_FORWARD_OPEN_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Candidate check for opening one channel.
 * An empty channel is CHANNEL. Liquidity below 1 is LIQUIDITY.
 * Replay of an existing channel is decided by the channel book.
 */
class SwarmForwardOpen {
public:
    bool Accept(const std::string& channel, int64_t liquidity, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FORWARD_OPEN_H
