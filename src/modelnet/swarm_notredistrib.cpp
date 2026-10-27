// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notredistrib.h>

#include <string>

namespace modelnet {

SwarmNotRedistribResult SwarmNoteNotRedistrib(const SwarmNotRedistrib& note, std::string& err)
{
    SwarmNotRedistribResult result;
    result.granted = false;
    result.bytes_moved = false;
    // A download license is not a redistribution grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.granted = false;
        result.bytes_moved = false;
        err = "LICENSE";
        return result;
    }
    if (note.want_redistribute) {
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
