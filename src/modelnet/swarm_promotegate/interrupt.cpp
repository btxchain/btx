// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/interrupt.h>

#include <modelnet/swarm_promotegate/codes.h>

namespace modelnet {

bool SwarmPromoteInterrupt::Apply(const SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const
{
    if (!slot.held()) {
        err = kSwarmPromoteStep;
        return false;
    }
    flag.mark();
    err.clear();
    return true;
}

} // namespace modelnet
