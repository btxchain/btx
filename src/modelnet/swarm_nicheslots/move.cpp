// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/move.h>

#include <modelnet/swarm_nicheslots/codes.h>

namespace modelnet {

bool SwarmNicheSlotsMove(const SwarmNicheSlotsTable& table, const std::string& task, const std::string& from,
                         const std::string& to, std::string& err)
{
    // Niches stay separate. The task is not copied and no slot is spent.
    (void)table;
    (void)task;
    (void)from;
    (void)to;
    err = kSwarmNicheSlotsNotMerged;
    return false;
}

} // namespace modelnet
