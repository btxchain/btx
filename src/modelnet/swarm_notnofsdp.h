// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTNOFSDP_H
#define BTX_MODELNET_SWARM_NOTNOFSDP_H

#include <string>

namespace modelnet {

/**
 * A local note about one step. want_distributed asks this note to treat one
 * local step as Fully Sharded Data Parallel (FSDP) distributed training.
 *
 * One local step is not FSDP. distributed and synced stay false on every path.
 */
struct SwarmNotNoFsdp {
    std::string step_id;
    bool want_distributed{false};
};

/**
 * Outcome of noting a distributed-step request. distributed and synced stay
 * false on every path: one local step is not FSDP.
 */
struct SwarmNotNoFsdpResult {
    std::string code;
    bool distributed{false};
    bool synced{false};
};

/**
 * Note a distributed-step request without treating one local step as FSDP.
 * Order, first match wins: an empty step_id is STEP.
 * want_distributed is NOT_DISTRIBUTED.
 * Otherwise the note is NOTED and err is clear.
 * distributed and synced stay false on every path.
 */
SwarmNotNoFsdpResult SwarmNoteNotNoFsdp(const SwarmNotNoFsdp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTNOFSDP_H
