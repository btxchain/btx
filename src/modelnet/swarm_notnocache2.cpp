// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocache2.h>

#include <string>

namespace modelnet {

SwarmNotNoCache2Result SwarmNoteNotNoCache2(const SwarmNotNoCache2& note, std::string& err)
{
    // A cache stands alone. Sharing it shares nothing and moves no bytes.
    SwarmNotNoCache2Result result;
    result.shared = false;
    result.bytes_moved = false;
    if (note.cache_id.empty()) {
        result.code = "CACHE";
        result.shared = false;
        result.bytes_moved = false;
        err = "CACHE";
        return result;
    }
    if (note.want_share) {
        result.code = "ALONE";
        result.shared = false;
        result.bytes_moved = false;
        err = "ALONE";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
