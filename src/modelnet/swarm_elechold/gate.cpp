// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_elechold/gate.h>

#include <modelnet/swarm_elechold/codes.h>
#include <modelnet/swarm_elechold/replay.h>
#include <modelnet/swarm_elechold/under.h>

namespace modelnet {

std::string SwarmElecHoldRefusal(const SwarmElecHoldBook& book, int64_t watt_hours)
{
    std::string err;
    if (!SwarmElecHoldUnder{}.accept(watt_hours, err)) return err;
    if (SwarmElecHoldIsReplay(book, watt_hours)) return std::string{kSwarmElecHoldReplay};
    return {};
}

} // namespace modelnet
