// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_leasework/bump.h>

namespace modelnet {

void LeaseWorkBump(LeaseWorkEpoch& epoch, LeaseWorkLeader& leader)
{
    epoch.Bump();
    leader.Clear();
}

} // namespace modelnet
