// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_NAME_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_NAME_H

#include <string>

namespace modelnet {

/**
 * Copies a shard name as the recorded name.
 * The characters are kept as written. No shard bytes are copied.
 * An empty name copies nothing.
 */
class SwarmShardHoldName {
public:
    std::string copy(const std::string& name) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_NAME_H
