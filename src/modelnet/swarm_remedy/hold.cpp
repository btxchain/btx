// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/hold.h>

namespace modelnet {

bool SwarmRemedyHold::broadcast() const
{
    return false;
}

int64_t SwarmRemedyHold::bytes_moved() const
{
    return 0;
}

bool SwarmRemedyHold::mined() const
{
    return false;
}

} // namespace modelnet
