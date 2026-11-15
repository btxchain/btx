// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_gradsync.h>

#include <cstdint>
#include <string>

namespace modelnet {

SwarmGradSyncResult SwarmNoteGradSync(const SwarmGradSync& update, std::string& err)
{
    SwarmGradSyncResult result;
    result.synced = false;
    result.bytes_moved = 0;
    // A gradient sync request is held and moves no bytes.
    if (update.update_id.empty()) {
        result.code = "UPDATE";
        result.synced = false;
        result.bytes_moved = 0;
        err = "UPDATE";
        return result;
    }
    if (update.want_sync) {
        result.code = "HELD";
        result.synced = false;
        result.bytes_moved = 0;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.synced = false;
    result.bytes_moved = 0;
    err.clear();
    return result;
}

} // namespace modelnet
