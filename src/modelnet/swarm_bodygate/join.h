// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_JOIN_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_JOIN_H

#include <modelnet/swarm_bodygate/piece.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Result of judging a stored size set.
 * bytes is the sum of stored sizes on success and 0 otherwise.
 * bytes_moved is 0. Join copies no payload.
 */
struct SwarmBodyJoinView {
    bool joined{false};
    std::string code;
    int64_t bytes{0};
    int64_t bytes_moved{0};
};

/**
 * Indexes must be exactly 0..n-1, with exactly one last piece, and that
 * last piece must be the highest index. A gap is GAP. A missing last
 * piece, an extra last piece, or a last piece that is not highest is LAST.
 * Success reports the stored-size sum. No bytes are moved.
 */
SwarmBodyJoinView SwarmBodyEvaluateJoin(const std::map<int64_t, SwarmBodyPiece>& pieces, int64_t stored_bytes);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_JOIN_H
