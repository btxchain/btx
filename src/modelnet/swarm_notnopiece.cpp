// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece.h>

namespace modelnet {

SwarmNotNoPieceResult SwarmNoteNotNoPiece(const SwarmNotNoPiece& note, std::string& err)
{
    // A piece split is 4 MiB and this note splits nothing.
    SwarmNotNoPieceResult result;
    result.split = false;
    result.applied_bytes = 0;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    if (note.size_bytes != 4194304) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    if (note.want_split) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
