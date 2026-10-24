// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_LEADER_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_LEADER_H

#include <string>

namespace modelnet {

class SwarmAgentRunLeases;

/**
 * Report leader loss without deleting.
 * Any stored lease is DURABLE. No stored lease is LOST.
 * Both paths return false. Leases, assignments, and receipts stay.
 */
bool SwarmAgentRunLeaderGone(const SwarmAgentRunLeases& leases, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_LEADER_H
