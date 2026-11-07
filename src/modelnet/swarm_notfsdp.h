// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_NOTFSDP_H
#define BTX_MODELNET_SWARM_NOTFSDP_H

#include <string>

namespace modelnet {

/**
 * A local note about one node. want_fsdp asks this note to treat one local
 * step as Fully Sharded Data Parallel (FSDP) distributed training.
 *
 * One local step is not FSDP and is not distributed training.
 * distributed stays false on every path.
 */
struct SwarmNotFsdp {
    std::string node_id;
    bool want_fsdp{false};
};

/**
 * Outcome of noting an FSDP request. distributed stays false on every path:
 * one local step is not FSDP and is not distributed training.
 */
struct SwarmNotFsdpResult {
    std::string code;
    bool distributed{false};
};

/**
 * Note an FSDP request without treating one local step as distributed training.
 * Order, first match wins: an empty node_id is TRAIN.
 * want_fsdp is NOT_DISTRIBUTED.
 * Otherwise the note is NOTED and err is clear.
 * distributed stays false on every path.
 */
SwarmNotFsdpResult SwarmNoteNotFsdp(const SwarmNotFsdp& note, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_NOTFSDP_H
