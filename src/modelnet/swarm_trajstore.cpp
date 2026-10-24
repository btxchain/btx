// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_trajstore.h>

#include <string>

namespace modelnet {

SwarmTrajStoreResult SwarmNoteTrajStore(const SwarmTrajStore& item, std::string& err)
{
    // A trajectory store request is held and stores nothing.
    SwarmTrajStoreResult result;
    result.stored = false;
    result.bytes_moved = 0;
    if (item.item_id.empty()) {
        result.code = "ITEM";
        result.stored = false;
        result.bytes_moved = 0;
        err = "ITEM";
        return result;
    }
    if (item.want_store) {
        result.code = "HELD";
        result.stored = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
