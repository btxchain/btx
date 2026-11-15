// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PROPOSE_H
#define BTX_MODELNET_SWARM_PROPOSE_H

#include <string>

namespace modelnet {

/**
 * A named experiment proposal. Scheduling it reserves one slot in memory.
 * This record does not train and does not move bytes.
 */
struct SwarmProposal {
    std::string weakness_id;
    std::string recipe_id;
    int slots{0};
    bool scheduled{false};
    bool trained{false};
};

/**
 * Schedule one slot when the weakness and recipe are named and the caller
 * still has a free slot. This function does not train and does not move bytes.
 */
bool SwarmProposeExperiment(SwarmProposal& proposal, int budget_slots, int used_slots, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PROPOSE_H
