// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece4b.h>

namespace modelnet {

SwarmNotNoPiece4bResult SwarmNoteNotNoPiece4b(const SwarmNotNoPiece4b& note, std::string& err)
{
    // A piece split is 4 MiB. This note splits nothing.
    SwarmNotNoPiece4bResult result;
    result.split = false;
    result.bytes_moved = false;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    if (note.bytes != 4194304) {
        result.code = "NOT_SPLIT";
        err = "NOT_SPLIT";
        return result;
    }
    if (note.want_split) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
