// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnocrossdedup2.h>

#include <string>

namespace modelnet {

SwarmNotNoCrossDedup2Result SwarmNoteNotNoCrossDedup2(const SwarmNotNoCrossDedup2& note, std::string& err)
{
    SwarmNotNoCrossDedup2Result result;
    result.moved = false;
    result.bytes_moved = false;
    if (note.realm_id.empty()) {
        result.code = "REALM";
        result.moved = false;
        result.bytes_moved = false;
        err = "REALM";
        return result;
    }
    // Cross-realm dedup moves no bytes.
    if (note.want_move) {
        result.code = "HELD";
        result.moved = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.moved = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
