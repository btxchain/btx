// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_NEARBY_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_NEARBY_H

#include <modelnet/swarm_execnbhd/record.h>

#include <vector>

namespace modelnet {

/**
 * Seat at most kSwarmExecNbhdNearbyCap admitted peers.
 * Lowest rtt_ms wins. Equal rtt_ms breaks by ascending peer id, bytewise.
 * Fewer admitted peers than the cap seats every one of them.
 * This selection does not connect.
 */
std::vector<SwarmExecNbhdRecord> SwarmExecNbhdSelectNearby(const std::vector<SwarmExecNbhdRecord>& eligible);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_NEARBY_H
