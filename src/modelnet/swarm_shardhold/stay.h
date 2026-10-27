// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_STAY_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_STAY_H

#include <string>

namespace modelnet {

/**
 * The stored request stays unsharded.
 * refusal() is HELD. sharded() stays false. running() stays false.
 * This type does not store a name and does not move bytes.
 */
class SwarmShardHoldStay {
public:
    std::string refusal() const;
    bool sharded() const;
    bool running() const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_STAY_H
