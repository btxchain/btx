// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SHARDHELD_H
#define BTX_MODELNET_SWARM_SHARDHELD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local note about one shard request. A shard request is held and
 * moves no bytes.
 */
struct SwarmShardHeld {
    std::string job_id;
    bool want_shard{false};
};

/**
 * Outcome of noting a shard request. sharded stays false and
 * bytes_moved stays 0 on every path. A shard request is held and
 * moves no bytes.
 */
struct SwarmShardHeldResult {
    std::string code;
    bool sharded{false};
    int64_t bytes_moved{0};
};

/**
 * Note a shard request without sharding.
 * Order, first match wins: an empty job_id is JOB. want_shard is HELD.
 * Otherwise the note is NOTED and err is cleared.
 * sharded stays false and bytes_moved stays 0 on every path.
 * A shard request is held and moves no bytes.
 */
SwarmShardHeldResult SwarmNoteShardHeld(const SwarmShardHeld& job, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SHARDHELD_H
