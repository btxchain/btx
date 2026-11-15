// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_BUMP_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_BUMP_H

#include <modelnet/swarm_leasework/epoch.h>
#include <modelnet/swarm_leasework/leader.h>

namespace modelnet {

/**
 * Move the fence epoch forward by one and clear the leader right to commit.
 * Stored grants are left where they are.
 */
void LeaseWorkBump(LeaseWorkEpoch& epoch, LeaseWorkLeader& leader);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_BUMP_H
