// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOSHARD2_H
#define BTX_MODELNET_SWARM_NOTNOSHARD2_H

#include <string>

namespace modelnet {

/**
 * A local note about one run. want_shard asks this note to shard.
 *
 * A shard request does not run multi-GPU.
 * ran stays false and gpus stays 0 on every path.
 */
struct SwarmNotNoShard2 {
    std::string run_id;
    bool want_shard{false};
};

/**
 * Outcome of noting a run. ran stays false and gpus stays 0 on every path.
 * A shard request does not run multi-GPU.
 */
struct SwarmNotNoShard2Result {
    std::string code;
    bool ran{false};
    int gpus{0};
};

/**
 * Note a run without sharding.
 * Order, first match wins: an empty run_id is RUN. want_shard is NOT_RUN.
 * Otherwise the note is NOTED and err is cleared.
 * ran stays false and gpus stays 0 on every path. A shard request does not
 * run multi-GPU.
 */
SwarmNotNoShard2Result SwarmNoteNotNoShard2(const SwarmNotNoShard2& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOSHARD2_H
