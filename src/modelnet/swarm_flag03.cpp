// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_flag03.h>

namespace modelnet {

SwarmFlag03Result SwarmStageCoordinate(const SwarmFlag03& in, std::string& err)
{
    SwarmFlag03Result result;
    result.persisted = false;
    result.ran = false;
    result.passed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    if (in.task_a.empty() || in.task_b.empty() || in.leader_id.empty()) {
        result.code = "TASK";
        err = "TASK";
        return result;
    }
    if (in.task_a == in.task_b) {
        result.code = "SAME_TASK";
        result.persisted = false;
        result.ran = false;
        err = "SAME_TASK";
        return result;
    }
    // Distinct tasks persist independently of the leader. A request to
    // run is not an execution.
    if (in.want_run) {
        result.code = "NOT_RUN";
        result.persisted = false;
        result.ran = false;
        err = "NOT_RUN";
        return result;
    }
    if (in.want_pass) {
        result.code = "UNQUALIFIED";
        result.persisted = false;
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    if (!in.durable) {
        result.code = "LOST";
        result.persisted = false;
        err = "LOST";
        return result;
    }
    // Evidence is retained locally. No task is executed.
    // persisted is true only when durable and the two task ids differ.
    result.code = "PERSISTED";
    result.persisted = true;
    result.ran = false;
    result.passed = false;
    result.bytes_moved = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
