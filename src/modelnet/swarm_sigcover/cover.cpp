// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/cover.h>

#include <modelnet/swarm_sigcover/codes.h>

#include <string>

namespace modelnet {

SwarmSigCoverPlan SwarmSigCoverPlanCover(bool already_covered, bool covers_outputs, std::string& err)
{
    SwarmSigCoverPlan plan;
    if (!covers_outputs) {
        // A first miss stores nothing. A later miss leaves a covered row covered.
        // Both misses are NOT_SIGNED. The plan carries no cover mark, so Apply
        // is not called and outputs_covered is not written.
        plan.accepted = false;
        plan.mark_covered = false;
        static_cast<void>(already_covered);
        err = SWARM_SIGCOVER_NOT_SIGNED;
        return plan;
    }
    if (already_covered) {
        plan.accepted = false;
        plan.mark_covered = false;
        err = SWARM_SIGCOVER_REPLAY;
        return plan;
    }
    plan.accepted = true;
    plan.mark_covered = true;
    plan.mark_preimage = false;
    err.clear();
    return plan;
}

} // namespace modelnet
