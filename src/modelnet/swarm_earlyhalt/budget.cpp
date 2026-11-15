// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/budget.h>

#include <modelnet/swarm_earlyhalt/codes.h>
#include <modelnet/swarm_earlyhalt/limits.h>

namespace modelnet {

bool SwarmEarlyHaltBudget::accept(int64_t budget, std::string& err) const
{
    if (budget < kSwarmEarlyHaltMinBudget) {
        err = kSwarmEarlyHaltBudget;
        return false;
    }
    return true;
}

} // namespace modelnet
