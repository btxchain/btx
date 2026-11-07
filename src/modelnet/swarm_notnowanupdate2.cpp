// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowanupdate2.h>

#include <string>

namespace modelnet {

SwarmNotNoWanUpdate2Result SwarmNoteNotNoWanUpdate2(const SwarmNotNoWanUpdate2& note, std::string& err)
{
    SwarmNotNoWanUpdate2Result result;
    result.exchanged = false;
    result.bytes_moved = false;
    // An island note exchanges no WAN update.
    if (note.island_id.empty()) {
        result.code = "ISLAND";
        result.exchanged = false;
        result.bytes_moved = false;
        err = "ISLAND";
        return result;
    }
    if (note.want_exchange) {
        result.code = "HELD";
        result.exchanged = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.exchanged = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
