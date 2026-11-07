// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopiece4m2.h>

namespace modelnet {

SwarmNotNoPiece4m2Result SwarmNoteNotNoPiece4m2(const SwarmNotNoPiece4m2& note, std::string& err)
{
    // A piece split stays 4194304 bytes.
    SwarmNotNoPiece4m2Result result;
    result.resized = false;
    result.bytes = 4194304;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        err = "PIECE";
        return result;
    }
    if (note.want_resize) {
        result.code = "HELD";
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
