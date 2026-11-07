// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocachealone.h>

#include <string>

namespace modelnet {

SwarmNotNoCacheAloneResult SwarmNoteNotNoCacheAlone(const SwarmNotNoCacheAlone& note, std::string& err)
{
    // A cache stands alone. Coupling it to another store shares nothing and moves no bytes.
    SwarmNotNoCacheAloneResult result;
    result.shared = false;
    result.bytes_moved = false;
    if (note.cache_id.empty()) {
        result.code = "CACHE";
        result.shared = false;
        result.bytes_moved = false;
        err = "CACHE";
        return result;
    }
    if (note.coupled) {
        result.code = "STANDS_ALONE";
        result.shared = false;
        result.bytes_moved = false;
        err = "STANDS_ALONE";
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
