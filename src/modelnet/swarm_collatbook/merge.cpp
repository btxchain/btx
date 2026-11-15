// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_collatbook/merge.h>

#include <modelnet/swarm_collatbook/codes.h>

namespace modelnet {

bool SwarmCollatMerge(std::string& err)
{
    // Rows stay where they are. Atoms are not moved.
    err = SWARM_COLLAT_NOT_MERGED;
    return false;
}

} // namespace modelnet
