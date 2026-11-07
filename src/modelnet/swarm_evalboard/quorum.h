// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_EVALBOARD_QUORUM_H
#define BITCOIN_MODELNET_SWARM_EVALBOARD_QUORUM_H

#include <modelnet/swarm_evalboard/report.h>

#include <vector>

namespace modelnet {

/**
 * True only when the stored rows have at least two distinct authors,
 * at least two distinct domains, and a high-minus-low score of at most
 * kSwarmEvalScoreSpread.
 * One row is false. Two rows that share a domain are false.
 * The rows are not modified and are not averaged.
 */
bool SwarmEvalAccepted(const std::vector<SwarmEvalReport>& rows);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_EVALBOARD_QUORUM_H
