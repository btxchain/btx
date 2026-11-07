// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_idledrain/open.h>

#include <modelnet/swarm_idledrain/replay.h>

namespace modelnet {

bool SwarmIdleDrainOpen::Apply(SwarmIdleDrainSeat& seat, SwarmIdleDrainWorkers& workers, std::string& err) const
{
    if (SwarmIdleDrainReplay{}.claimed(seat.opened(), err)) {
        return false;
    }
    seat.admit();
    workers.start();
    err.clear();
    return true;
}

} // namespace modelnet
