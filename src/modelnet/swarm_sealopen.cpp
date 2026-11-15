// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_sealopen.h>

namespace modelnet {

// A sealed piece is not opened.
SwarmSealOpenResult SwarmNoteSealOpen(const SwarmSealOpen& piece, std::string& err)
{
    SwarmSealOpenResult result;
    result.opened = false;

    if (piece.piece_id.empty()) {
        result.code = "PIECE";
        result.opened = false;
        err = "PIECE";
        return result;
    }
    if (piece.sealed) {
        result.code = "NOT_OPENED";
        result.opened = false;
        err = "NOT_OPENED";
        return result;
    }
    if (piece.want_open) {
        result.code = "HELD";
        result.opened = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.opened = false;
    err.clear();
    return result;
}

} // namespace modelnet
