// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvnomove.h>

namespace modelnet {

SwarmKvNoMoveResult SwarmNoteKvNoMove(const SwarmKvNoMove& note, std::string& err)
{
    SwarmKvNoMoveResult result;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "KV";
        result.bytes_moved = false;
        err = "KV";
        return result;
    }
    // An engine flag is not a KV transfer.
    if (!note.engine_present) {
        result.code = "ENGINE_ABSENT";
        result.bytes_moved = false;
        err = "ENGINE_ABSENT";
        return result;
    }
    if (note.want_transfer) {
        result.code = "HELD";
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
