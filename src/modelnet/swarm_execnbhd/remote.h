// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_REMOTE_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_REMOTE_H

#include <modelnet/swarm_execnbhd/record.h>

#include <vector>

namespace modelnet {

/**
 * Seat at most kSwarmExecNbhdRemoteCap peers that were not seated nearby
 * and whose trust domain is not already present in the nearby set.
 * Lowest rtt_ms wins, then ascending peer id, bytewise.
 * Once that many peers are chosen, a later domain stays unseated.
 * A peer whose domain is already in the nearby set cannot fill a slot.
 * Fewer candidates than the cap seats every one of them.
 * This selection does not connect.
 */
std::vector<SwarmExecNbhdRecord> SwarmExecNbhdSelectRemote(const std::vector<SwarmExecNbhdRecord>& eligible,
                                                           const std::vector<SwarmExecNbhdRecord>& nearby);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_REMOTE_H
