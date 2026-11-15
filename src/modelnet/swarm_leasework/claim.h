// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LEASEWORK_CLAIM_H
#define BITCOIN_MODELNET_SWARM_LEASEWORK_CLAIM_H

#include <modelnet/swarm_leasework/book.h>
#include <modelnet/swarm_leasework/leader.h>

#include <string>

namespace modelnet {

/**
 * Give the commit right to a worker that already holds a live grant.
 * An empty worker is TASK. A second claim is REPLAY and keeps the first
 * leader. A worker with no stored grant is TASK. A worker whose grants
 * are all past the observed clock is EXPIRED. Nothing is launched.
 */
bool LeaseWorkClaim(LeaseWorkBook& book, LeaseWorkLeader& leader, const std::string& worker, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LEASEWORK_CLAIM_H
