// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradexp.h>

#include <string>

namespace modelnet {

SwarmNotNoGradExpResult SwarmNoteNotNoGradExp(const SwarmNotNoGradExp& note, std::string& err)
{
    SwarmNotNoGradExpResult result;
    result.exported = false;
    result.bytes_moved = false;
    if (note.update_id.empty()) {
        result.code = "UPDATE";
        result.exported = false;
        result.bytes_moved = false;
        err = "UPDATE";
        return result;
    }
    // A gradient update is not exported.
    if (note.want_export) {
        result.code = "NOT_EXPORTED";
        result.exported = false;
        result.bytes_moved = false;
        err = "NOT_EXPORTED";
        return result;
    }
    result.code = "NOTED";
    result.exported = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
