// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_traincohort/remote.h>

#include <modelnet/swarm_traincohort/error.h>

namespace modelnet {

bool CohortOfferRemote(TrainCohortMember& member, uint64_t remote_step, const std::string& hash, std::string& err)
{
    if (remote_step <= member.step) {
        err = COHORT_STALE;
        return false;
    }
    if (remote_step != member.step + 1) {
        err = COHORT_GAP;
        return false;
    }
    member.pending_hash = hash;
    member.pending = true;
    err.clear();
    return true;
}

} // namespace modelnet
