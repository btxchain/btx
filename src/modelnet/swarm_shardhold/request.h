// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_REQUEST_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_REQUEST_H

#include <modelnet/swarm_shardhold/book.h>

#include <string>

namespace modelnet {

/**
 * Records one shard request and leaves it unsharded.
 * An empty name is SHARD and the book stays as it was.
 * A new non-empty name is stored. The call returns false and err is HELD.
 * A second Request of the same name is REPLAY and leaves the first request.
 * Those checks run in that order. Nothing is sharded and no bytes move.
 * running() stays false.
 */
class SwarmShardHoldRequest {
public:
    bool Apply(SwarmShardHoldBook& book, const std::string& name, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_REQUEST_H
