// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoredist.h>

#include <string>

namespace modelnet {

SwarmNotNoRedistResult SwarmNoteNotNoRedist(const SwarmNotNoRedist& note, std::string& err)
{
    SwarmNotNoRedistResult result;
    result.redistributed = false;
    result.bytes_moved = false;
    // A download license is not a redistribution grant and moves no bytes.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.redistributed = false;
        result.bytes_moved = false;
        err = "LICENSE";
        return result;
    }
    if (note.want_redistribute) {
        result.code = "NOT_GRANT";
        result.redistributed = false;
        result.bytes_moved = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.redistributed = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
