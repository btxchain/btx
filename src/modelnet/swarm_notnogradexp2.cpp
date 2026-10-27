// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogradexp2.h>

#include <string>

namespace modelnet {

SwarmNotNoGradExp2Result SwarmNoteNotNoGradExp2(const SwarmNotNoGradExp2& note, std::string& err)
{
    // A gradient update is not exported.
    SwarmNotNoGradExp2Result result;
    result.exported = false;
    result.bytes_moved = false;
    if (note.update_id.empty()) {
        result.code = "UPDATE";
        result.exported = false;
        result.bytes_moved = false;
        err = "UPDATE";
        return result;
    }
    if (note.gradient) {
        result.code = "NOT_EXPORTED";
        result.exported = false;
        result.bytes_moved = false;
        err = "NOT_EXPORTED";
        return result;
    }
    if (note.want_export) {
        result.code = "HELD";
        result.exported = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.exported = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
