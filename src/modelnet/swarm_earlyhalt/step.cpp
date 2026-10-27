// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/step.h>

#include <modelnet/swarm_earlyhalt/codes.h>
#include <modelnet/swarm_earlyhalt/stop.h>

namespace modelnet {

bool SwarmEarlyHaltStep::Apply(SwarmEarlyHaltSeat& seat, SwarmEarlyHaltRemain& remain, SwarmEarlyHaltScore& score, SwarmEarlyHaltMark& mark, int64_t next, std::string& err) const
{
    if (!seat.opened()) {
        err = kSwarmEarlyHaltStep;
        return false;
    }
    if (mark.set() || remain.exhausted()) {
        err = kSwarmEarlyHaltStopped;
        return false;
    }
    const bool fell = score.lower_than(next);
    remain.spend();
    score.store(next);
    if (fell) {
        SwarmEarlyHaltStop{}.Apply(remain, mark);
    }
    err.clear();
    return true;
}

} // namespace modelnet
