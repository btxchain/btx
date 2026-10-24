// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_PIECE_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_PIECE_H

#include <modelnet/swarm_bodygate/limits.h>

#include <cstdint>

namespace modelnet {

/**
 * One piece offer. The gate stores this size and the last flag.
 * It does not store a payload.
 */
struct SwarmBodyPiece {
    int64_t index{0};
    int64_t size{0};
    bool last{false};
};

/** Why a piece offer is refused before any store, replay, or body check. */
enum class SwarmBodyPieceFault {
    None,
    Index,
    Short,
};

/**
 * Index and size rules for one piece.
 * index < 0 is Index. size < 1 is Short.
 * A non-last piece whose size is not the piece size is Short.
 * A last piece larger than the piece size is Short.
 * None means the offer may be considered for storage.
 */
SwarmBodyPieceFault SwarmBodyClassifyPiece(int64_t index, int64_t size, bool last);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_PIECE_H
