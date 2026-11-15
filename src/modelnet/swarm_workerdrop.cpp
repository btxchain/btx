// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workerdrop.h>

namespace modelnet {
namespace {

SwarmWorkerDropResult Reject(const std::string& code, std::string& err)
{
    SwarmWorkerDropResult result;
    result.executed = false;
    result.result_kept = false;
    result.code = code;
    err = code;
    return result;
}

SwarmWorkerDropResult Keep(const std::string& code, std::string& err)
{
    SwarmWorkerDropResult result;
    result.executed = false;
    result.result_kept = true;
    result.code = code;
    err.clear();
    return result;
}

} // namespace

SwarmWorkerDropResult SwarmNoteWorkerDrop(const SwarmWorkerDropRequest& request, std::string& err)
{
    if (request.task_id.empty() || request.worker_id.empty()) {
        return Reject("WORKER", err);
    }
    if (!request.result_stored) {
        return Reject("RESULT_ABSENT", err);
    }
    if (!request.worker_connected) {
        return Keep("DROPPED", err);
    }
    return Keep("NOTED", err);
}

} // namespace modelnet
