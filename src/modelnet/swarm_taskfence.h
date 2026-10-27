// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_TASKFENCE_H
#define BTX_MODELNET_SWARM_TASKFENCE_H

#include <cstdint>
#include <string>

namespace modelnet {

enum class SwarmTaskState { Queued, Running, Cancelling, Cancelled, Complete, Failed };

struct SwarmTaskClaim {
    std::string task_id;
    std::string worker_id;
    int64_t term{0};
    int64_t generation{0};
    SwarmTaskState state{SwarmTaskState::Queued};
    bool result_kept{false};
};

/** An empty task or worker, or a negative term or generation, is CLAIM. */
bool SwarmClaimTask(SwarmTaskClaim& claim, const std::string& task_id, const std::string& worker_id, int64_t term,
                    int64_t generation, std::string& err);

/**
 * A term that does not move forward is STALE_TERM.
 * Running is requeued to Queued. result_kept stays as it was.
 */
bool SwarmAdvanceTerm(SwarmTaskClaim& claim, int64_t new_term, std::string& err);

/**
 * An empty task is CLAIM. The state passes through Cancelling.
 * This function is not a process: it sets Cancelled and result_kept.
 * It does not erase a result.
 */
bool SwarmCancelTask(SwarmTaskClaim& claim, std::string& err);

/**
 * Work above collateral without acceptance is CONSERVATION.
 * Acceptance with an empty terms id is TERMS.
 * This function does not spend or broadcast. Automatic spend is not a field.
 */
bool SwarmAcceptUnsecured(bool above_collateral, bool accept_unsecured, const std::string& terms_id, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_TASKFENCE_H
