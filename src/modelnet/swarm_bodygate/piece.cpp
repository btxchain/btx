// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_bodygate/piece.h>

namespace modelnet {

SwarmBodyPieceFault SwarmBodyClassifyPiece(int64_t index, int64_t size, bool last)
{
    if (index < 0) {
        return SwarmBodyPieceFault::Index;
    }
    if (size < 1) {
        return SwarmBodyPieceFault::Short;
    }
    if (!last && size != kSwarmBodyGatePieceBytes) {
        return SwarmBodyPieceFault::Short;
    }
    if (last && size > kSwarmBodyGatePieceBytes) {
        return SwarmBodyPieceFault::Short;
    }
    return SwarmBodyPieceFault::None;
}

} // namespace modelnet
