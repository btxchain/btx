// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SHARDHOLD_CODES_H
#define BITCOIN_MODELNET_SWARM_SHARDHOLD_CODES_H

namespace modelnet {

/** Empty name. Nothing is stored. */
inline constexpr char kSwarmShardHoldShard[] = "SHARD";

/** A second Request of a name already stored. The first request stays. */
inline constexpr char kSwarmShardHoldReplay[] = "REPLAY";

/**
 * The name is stored and the shard is refused.
 * sharded() stays false. running() stays false.
 */
inline constexpr char kSwarmShardHoldHeld[] = "HELD";

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SHARDHOLD_CODES_H
