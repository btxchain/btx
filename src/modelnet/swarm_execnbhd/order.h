// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EXECNBHD_ORDER_H
#define BITCOIN_MODELNET_SWARM_EXECNBHD_ORDER_H

#include <modelnet/swarm_execnbhd/record.h>

#include <vector>

namespace modelnet {

/**
 * True when left is seated before right.
 * Lower rtt_ms wins. Equal rtt_ms breaks by ascending peer id, bytewise.
 */
bool SwarmExecNbhdPrecedes(const SwarmExecNbhdRecord& left, const SwarmExecNbhdRecord& right);

/** Sort rows in seating order. The vector is reordered in place. */
void SwarmExecNbhdRank(std::vector<SwarmExecNbhdRecord>& rows);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EXECNBHD_ORDER_H
