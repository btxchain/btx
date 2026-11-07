// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_SPAN_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_SPAN_H

#include <modelnet/swarm_bodygate/piece.h>

#include <map>

namespace modelnet {

/**
 * True when the stored indexes are exactly 0..n-1.
 * An empty set is the empty range and is contiguous.
 * A missing index, or a set that does not start at 0, is a gap.
 */
bool SwarmBodyIndexesContiguous(const std::map<int64_t, SwarmBodyPiece>& pieces);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_SPAN_H
