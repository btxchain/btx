// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoid.h>

#include <string>

namespace modelnet {

SwarmNotNoIdResult SwarmNoteNotNoId(const SwarmNotNoId& note, std::string& err)
{
    SwarmNotNoIdResult result;
    result.granted = false;
    result.bytes_moved = false;
    // An identity note grants no license and moves no bytes.
    if (note.identity_id.empty()) {
        result.code = "IDENTITY";
        result.granted = false;
        result.bytes_moved = false;
        err = "IDENTITY";
        return result;
    }
    if (note.want_grant) {
        result.code = "NOT_GRANT";
        result.granted = false;
        result.bytes_moved = false;
        err = "NOT_GRANT";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
