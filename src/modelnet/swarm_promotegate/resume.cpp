// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_promotegate/resume.h>

#include <modelnet/swarm_promotegate/codes.h>

namespace modelnet {

bool SwarmPromoteResume::Apply(const SwarmPromoteFlag& flag, std::string& err) const
{
    if (flag.marked()) {
        err = kSwarmPromoteInterrupted;
        return false;
    }
    err = kSwarmPromoteStep;
    return false;
}

} // namespace modelnet
