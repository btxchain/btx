// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/open.h>

#include <modelnet/swarm_earlyhalt/budget.h>
#include <modelnet/swarm_earlyhalt/codes.h>

namespace modelnet {

bool SwarmEarlyHaltOpen::Apply(SwarmEarlyHaltSeat& seat, SwarmEarlyHaltRemain& remain, int64_t budget, std::string& err) const
{
    if (!SwarmEarlyHaltBudget{}.accept(budget, err)) {
        return false;
    }
    if (seat.opened()) {
        err = kSwarmEarlyHaltReplay;
        return false;
    }
    seat.admit(budget);
    remain.arm(budget);
    err.clear();
    return true;
}

} // namespace modelnet
