// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_nottrunc.h>

#include <string>

namespace modelnet {

SwarmNotTruncResult SwarmNoteNotTrunc(const SwarmNotTrunc& note, std::string& err)
{
    SwarmNotTruncResult result;
    result.accepted = false;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.accepted = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    // A truncated or incompatible transferred cache has not been shown on a live tensor.
    if (note.want_accept) {
        result.code = "NOT_SHOWN";
        result.accepted = false;
        result.bytes_moved = false;
        err = "NOT_SHOWN";
        return result;
    }
    result.code = "NOTED";
    result.accepted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
