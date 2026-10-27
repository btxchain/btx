// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSHARD_H
#define BTX_MODELNET_SWARM_NOTNOSHARD_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_shard asks this note to shard.
 *
 * A shard request does not run multi-GPU training.
 * sharded and gpu stay false on every path.
 */
struct SwarmNotNoShard {
    std::string run_id;
    bool want_shard{false};
};

/**
 * Outcome of noting a run. sharded and gpu stay false on every path.
 * A shard request does not run multi-GPU training.
 */
struct SwarmNotNoShardResult {
    std::string code;
    bool sharded{false};
    bool gpu{false};
};

/**
 * Note a run without sharding.
 * Order, first match wins: an empty run_id is RUN. want_shard is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * sharded and gpu stay false on every path. A shard request does not run
 * multi-GPU training.
 */
SwarmNotNoShardResult SwarmNoteNotNoShard(const SwarmNotNoShard& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSHARD_H
