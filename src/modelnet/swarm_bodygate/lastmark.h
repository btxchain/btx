// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_LASTMARK_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_LASTMARK_H

#include <modelnet/swarm_bodygate/piece.h>

#include <map>

namespace modelnet {

/**
 * True when exactly one stored piece is marked last and that piece
 * holds the highest index. An empty set, a missing last mark, more
 * than one last mark, or a last mark on a lower index is false.
 */
bool SwarmBodyLastIsHighest(const std::map<int64_t, SwarmBodyPiece>& pieces);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_LASTMARK_H
