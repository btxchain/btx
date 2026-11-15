// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_GATE_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_GATE_H

#include <modelnet/swarm_shardhold/book.h>

#include <string>

namespace modelnet {

/**
 * What Request should do with name.
 * code is SHARD, REPLAY, or empty when the name may be stored.
 * store is true only for a new non-empty name.
 * Storing the name does not shard it. This function does not modify the book.
 */
struct SwarmShardHoldDecision {
    std::string code;
    bool store{false};
};

/**
 * Refusal or keep decision for Request.
 * An empty name is SHARD and is not stored.
 * A name already stored is REPLAY. The first request stays.
 * Any other name may be stored. The caller then returns HELD.
 * SHARD is decided before REPLAY. REPLAY is decided before HELD.
 */
SwarmShardHoldDecision SwarmShardHoldDecide(const SwarmShardHoldBook& book, const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_GATE_H
