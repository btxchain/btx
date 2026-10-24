// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_propose.h>

namespace modelnet {

bool SwarmProposeExperiment(SwarmProposal& proposal, int budget_slots, int used_slots, std::string& err)
{
    if (proposal.weakness_id.empty() || proposal.recipe_id.empty()) {
        proposal.scheduled = false;
        proposal.trained = false;
        err = "PROPOSE";
        return false;
    }
    if (budget_slots <= 0 || used_slots < 0) {
        proposal.scheduled = false;
        proposal.trained = false;
        err = "BUDGET";
        return false;
    }
    if (used_slots >= budget_slots) {
        proposal.scheduled = false;
        proposal.trained = false;
        err = "BUDGET";
        return false;
    }
    proposal.slots = 1;
    proposal.scheduled = true;
    proposal.trained = false;
    err.clear();
    return true;
}

} // namespace modelnet
