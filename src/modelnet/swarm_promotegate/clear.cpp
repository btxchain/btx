// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/clear.h>

namespace modelnet {

bool SwarmPromoteClear::Apply(SwarmPromoteCandidate& slot, SwarmPromoteFlag& flag, std::string& err) const
{
    slot.clear();
    flag.clear();
    err.clear();
    return true;
}

} // namespace modelnet
