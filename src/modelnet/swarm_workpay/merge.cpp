// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workpay/merge.h>

#include <modelnet/swarm_workpay/codes.h>

namespace modelnet {

bool SwarmWorkMerge(std::string& err)
{
    // The earned counter stays where it is. Nothing is moved.
    err = SWARM_WORK_NOT_MERGED;
    return false;
}

} // namespace modelnet
