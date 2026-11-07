// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/bucket.h>

#include <modelnet/swarm_collatbook/codes.h>
#include <modelnet/swarm_collatbook/limits.h>

namespace modelnet {

bool SwarmCollatAcceptBucket(const std::string& bucket, std::string& err)
{
    if (bucket == kSwarmCollatEscrow || bucket == kSwarmCollatCollateral) {
        err.clear();
        return true;
    }
    err = SWARM_COLLAT_BUCKET;
    return false;
}

} // namespace modelnet
