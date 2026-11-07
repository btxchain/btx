// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_ADMINHOLD_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_ADMINHOLD_CHANNEL_H

#include <string>

namespace modelnet {

/**
 * Accepts a channel id that can be stored.
 * An empty channel is CHANNEL. The caller stores nothing on that result.
 */
class SwarmAdminHoldChannel {
public:
    bool accept(const std::string& channel, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_ADMINHOLD_CHANNEL_H
