// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/spend.h>

#include <modelnet/swarm_nicheslots/codes.h>
#include <modelnet/swarm_nicheslots/names.h>

namespace modelnet {

bool SwarmNicheSlotsSpend(SwarmNicheSlotsTable& table, const std::string& niche, const std::string& task,
                          std::string& err)
{
    if (!SwarmNicheSlotsKnown(niche)) {
        err = kSwarmNicheSlotsNiche;
        return false;
    }
    if (task.empty()) {
        err = kSwarmNicheSlotsTask;
        return false;
    }
    if (!table.opened(niche)) {
        err = kSwarmNicheSlotsNiche;
        return false;
    }
    if (table.has_task(niche, task)) {
        err = kSwarmNicheSlotsReplay;
        return false;
    }
    if (table.remaining(niche) == 0) {
        err = kSwarmNicheSlotsExhausted;
        return false;
    }
    table.Spend(niche, task);
    err.clear();
    return true;
}

} // namespace modelnet
