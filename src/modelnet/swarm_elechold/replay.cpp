// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/replay.h>

#include <modelnet/swarm_elechold/watthour.h>

namespace modelnet {

bool SwarmElecHoldIsReplay(const SwarmElecHoldBook& book, int64_t watt_hours)
{
    if (!SwarmElecHoldStorable(watt_hours)) return false;
    return book.measured();
}

} // namespace modelnet
