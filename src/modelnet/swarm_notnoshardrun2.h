// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSHARDRUN2_H
#define BTX_MODELNET_SWARM_NOTNOSHARDRUN2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_shard asks this note to shard.
 *
 * Sharding has not run and this note shards nothing.
 * sharded stays false and bytes_moved stays false on every path.
 */
struct SwarmNotNoShardRun2 {
    std::string run_id;
    bool want_shard{false};
};

/**
 * Outcome of noting a shard run request. sharded stays false and
 * bytes_moved stays false on every path. Sharding has not run and this
 * note shards nothing.
 */
struct SwarmNotNoShardRun2Result {
    std::string code;
    bool sharded{false};
    bool bytes_moved{false};
};

/**
 * Note a shard run request without sharding.
 * Order, first match wins: an empty run_id is RUN.
 * want_shard is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * sharded stays false and bytes_moved stays false on every path.
 * Sharding has not run and this note shards nothing.
 */
SwarmNotNoShardRun2Result SwarmNoteNotNoShardRun2(const SwarmNotNoShardRun2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSHARDRUN2_H
