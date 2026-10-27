// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoplace.h>

#include <string>

namespace modelnet {

SwarmNotNoPlaceResult SwarmNoteNotNoPlace(const SwarmNotNoPlace& note, std::string& err)
{
    SwarmNotNoPlaceResult result;
    result.placed = false;
    result.bytes_moved = false;
    // A placement note moves no bytes.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.placed = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.want_place) {
        result.code = "NOT_PLACED";
        result.placed = false;
        result.bytes_moved = false;
        err = "NOT_PLACED";
        return result;
    }
    result.code = "NOTED";
    result.placed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
