// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_piecelen.h>

namespace modelnet {

bool SwarmPieceLen::Accept(int64_t size, bool last, std::string& err)
{
    if (size < 1) {
        err = "SHORT";
        return false;
    }
    if (!last && size != PIECE) {
        err = "SHORT";
        return false;
    }
    if (last && size > PIECE) {
        err = "SHORT";
        return false;
    }
    err.clear();
    return true;
}

int64_t SwarmPieceLen::piece_bytes() const
{
    return PIECE;
}

bool SwarmPieceLen::bytes_moved() const
{
    return false;
}

} // namespace modelnet
