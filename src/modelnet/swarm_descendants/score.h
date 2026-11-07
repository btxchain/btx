// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_SCORE_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_SCORE_H

#include <modelnet/swarm_descendants/node.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Store one independent score on an existing node.
 * Author equal to the node id is NOT_SCORED. independent false is HELD.
 * A second score from the same author is REPLAY and keeps the first score.
 * Two distinct authors whose scores differ by at most
 * kDescendantScoreSpread set accepted. Scores are not averaged.
 * own_head and parent are left unchanged.
 */
bool MeasureDescendant(SwarmDescendantNode& node, const std::string& author, bool independent, int64_t score, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_SCORE_H
