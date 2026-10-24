// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nicheslots/open.h>

#include <modelnet/swarm_nicheslots/codes.h>
#include <modelnet/swarm_nicheslots/limits.h>
#include <modelnet/swarm_nicheslots/names.h>

namespace modelnet {

bool SwarmNicheSlotsOpen(SwarmNicheSlotsTable& table, const std::string& niche, int64_t slots, std::string& err)
{
    if (!SwarmNicheSlotsKnown(niche)) {
        err = kSwarmNicheSlotsNiche;
        return false;
    }
    if (table.opened(niche)) {
        err = kSwarmNicheSlotsReplay;
        return false;
    }
    if (slots < kSwarmNicheSlotsMin) {
        err = kSwarmNicheSlotsSlots;
        return false;
    }
    table.Open(niche, slots);
    err.clear();
    return true;
}

} // namespace modelnet
