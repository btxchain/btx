// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocachealone2.h>

namespace modelnet {

SwarmNotNoCacheAlone2Result SwarmNoteNotNoCacheAlone2(const SwarmNotNoCacheAlone2& note, std::string& err)
{
    // A cache stands alone and is not shared.
    SwarmNotNoCacheAlone2Result result;
    result.shared = false;
    if (note.cache_id.empty()) {
        result.code = "CACHE";
        err = "CACHE";
        result.shared = false;
        return result;
    }
    if (note.want_share) {
        result.code = "HELD";
        err = "HELD";
        result.shared = false;
        return result;
    }
    result.code = "NOTED";
    err.clear();
    result.shared = false;
    return result;
}

} // namespace modelnet
