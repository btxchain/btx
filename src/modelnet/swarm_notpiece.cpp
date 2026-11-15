// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notpiece.h>

namespace modelnet {

SwarmNotPieceResult SwarmNoteNotPiece(const SwarmNotPiece& note, std::string& err)
{
    // The piece size is 4 MiB and this note does not split or move bytes.
    SwarmNotPieceResult result;
    result.split = false;
    result.bytes_moved = false;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    if (note.size_bytes != 4194304 || note.want_split) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
