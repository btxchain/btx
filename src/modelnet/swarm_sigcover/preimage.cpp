// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sigcover/preimage.h>

#include <modelnet/swarm_sigcover/codes.h>
#include <modelnet/swarm_sigcover/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmSigCoverPlan SwarmSigCoverPlanPreimage(bool preimage_described, int64_t length, std::string& err)
{
    SwarmSigCoverPlan plan;
    if (length != kSwarmSigCoverPreimageLen) {
        // 31 and every other length store nothing. A stored 32 is left in place.
        plan.accepted = false;
        plan.mark_preimage = false;
        static_cast<void>(preimage_described);
        err = SWARM_SIGCOVER_PREIMAGE;
        return plan;
    }
    if (preimage_described) {
        plan.accepted = false;
        plan.mark_preimage = false;
        err = SWARM_SIGCOVER_REPLAY;
        return plan;
    }
    plan.accepted = true;
    plan.mark_covered = false;
    plan.mark_preimage = true;
    err.clear();
    return plan;
}

} // namespace modelnet
