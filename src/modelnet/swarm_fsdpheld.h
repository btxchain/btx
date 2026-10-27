// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_FSDPHELD_H
#define BTX_MODELNET_SWARM_FSDPHELD_H

#include <string>

namespace modelnet {

/**
 * An FSDP run request is held. job_id names the job. want_run asks this
 * note to run.
 *
 * An FSDP run request is held and does not run.
 * running stays false and sharded stays false on every path.
 */
struct SwarmFsdpHeld {
    std::string job_id;
    bool want_run{false};
};

/**
 * Outcome of noting a held FSDP run request. running stays false and
 * sharded stays false on every path.
 */
struct SwarmFsdpHeldResult {
    std::string code;
    bool running{false};
    bool sharded{false};
};

/**
 * Note a held FSDP run request. It does not run and does not shard.
 * Order, first match wins: an empty job_id is JOB.
 * want_run true is HELD.
 * Otherwise the code is NOTED and err is cleared.
 * running stays false and sharded stays false on every path.
 * An FSDP run request is held and does not run.
 */
SwarmFsdpHeldResult SwarmNoteFsdpHeld(const SwarmFsdpHeld& job, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_FSDPHELD_H
