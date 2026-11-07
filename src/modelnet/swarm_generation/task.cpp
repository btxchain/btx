// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_generation/task.h>

#include <modelnet/swarm_generation/codes.h>

namespace modelnet {

bool SwarmGenerationSelectTask::Apply(SwarmGenerationStrategy& strategy, const std::string& task, bool data_grant, std::string& err) const
{
    if (task.empty()) {
        return SwarmGenerationFail(err, kSwarmGenerationTask);
    }
    // An experiment id requires the data grant. A refused grant stores nothing.
    if (!data_grant) {
        return SwarmGenerationFail(err, kSwarmGenerationData);
    }
    strategy.add_task(task);
    return SwarmGenerationOk(err);
}

} // namespace modelnet
