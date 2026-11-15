// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomine.h>

#include <string>

namespace modelnet {

SwarmNotNoMineResult SwarmNoteNotNoMine(const SwarmNotNoMine& note, std::string& err)
{
    SwarmNotNoMineResult result;
    result.mined = false;
    result.broadcast = false;
    if (note.chain_id.empty()) {
        result.code = "CHAIN";
        result.mined = false;
        result.broadcast = false;
        err = "CHAIN";
        return result;
    }
    // A mine request is not mined and is not broadcast.
    if (note.want_mine) {
        result.code = "NOT_MINED";
        result.mined = false;
        result.broadcast = false;
        err = "NOT_MINED";
        return result;
    }
    result.code = "NOTED";
    result.mined = false;
    result.broadcast = false;
    err.clear();
    return result;
}

} // namespace modelnet
