// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoredist2.h>

#include <string>

namespace modelnet {

SwarmNotNoRedist2Result SwarmNoteNotNoRedist2(const SwarmNotNoRedist2& note, std::string& err)
{
    SwarmNotNoRedist2Result result;
    result.granted = false;
    // A download license is not a redistribution grant.
    if (note.license_id.empty()) {
        result.code = "LICENSE";
        result.granted = false;
        err = "LICENSE";
        return result;
    }
    if (note.download) {
        result.code = "NOT_REDIST";
        result.granted = false;
        err = "NOT_REDIST";
        return result;
    }
    if (note.want_grant) {
        result.code = "HELD";
        result.granted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.granted = false;
    err.clear();
    return result;
}

} // namespace modelnet
