// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_taskfence.h>

namespace modelnet {

bool SwarmClaimTask(SwarmTaskClaim& claim, const std::string& task_id, const std::string& worker_id, int64_t term,
                    int64_t generation, std::string& err)
{
    if (task_id.empty() || worker_id.empty() || term < 0 || generation < 0) {
        err = "CLAIM";
        return false;
    }
    claim.task_id = task_id;
    claim.worker_id = worker_id;
    claim.term = term;
    claim.generation = generation;
    claim.state = SwarmTaskState::Running;
    claim.result_kept = false;
    err.clear();
    return true;
}

bool SwarmAdvanceTerm(SwarmTaskClaim& claim, int64_t new_term, std::string& err)
{
    if (new_term <= claim.term) {
        err = "STALE_TERM";
        return false;
    }
    if (claim.state == SwarmTaskState::Running) {
        claim.state = SwarmTaskState::Queued;
    }
    claim.term = new_term;
    err.clear();
    return true;
}

bool SwarmCancelTask(SwarmTaskClaim& claim, std::string& err)
{
    if (claim.task_id.empty()) {
        err = "CLAIM";
        return false;
    }
    claim.state = SwarmTaskState::Cancelling;
    // The caller is not a process. Cancellation does not wait for one.
    claim.state = SwarmTaskState::Cancelled;
    claim.result_kept = true;
    err.clear();
    return true;
}

bool SwarmAcceptUnsecured(bool above_collateral, bool accept_unsecured, const std::string& terms_id, std::string& err)
{
    if (!above_collateral) {
        err.clear();
        return true;
    }
    if (!accept_unsecured) {
        err = "CONSERVATION";
        return false;
    }
    if (terms_id.empty()) {
        err = "TERMS";
        return false;
    }
    err.clear();
    return true;
}

} // namespace modelnet
