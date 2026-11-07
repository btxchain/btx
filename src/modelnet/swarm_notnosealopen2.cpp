// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosealopen2.h>

#include <string>

namespace modelnet {

SwarmNotNoSealOpen2Result SwarmNoteNotNoSealOpen2(const SwarmNotNoSealOpen2& note, std::string& err)
{
    SwarmNotNoSealOpen2Result result;
    result.opened = false;
    if (note.piece_id.empty()) {
        result.code = "PIECE";
        result.opened = false;
        err = "PIECE";
        return result;
    }
    // A sealed piece opens nothing.
    if (note.sealed) {
        result.code = "NOT_OPENED";
        result.opened = false;
        err = "NOT_OPENED";
        return result;
    }
    if (note.want_open) {
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
