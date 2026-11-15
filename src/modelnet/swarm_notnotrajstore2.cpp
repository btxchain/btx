// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotrajstore2.h>

#include <string>

namespace modelnet {

SwarmNotNoTrajStore2Result SwarmNoteNotNoTrajStore2(const SwarmNotNoTrajStore2& note, std::string& err)
{
    SwarmNotNoTrajStore2Result result;
    result.stored = false;
    result.bytes_moved = false;
    // A trajectory store has not run and this note stores nothing.
    if (note.store_id.empty()) {
        result.code = "STORE";
        result.stored = false;
        result.bytes_moved = false;
        err = "STORE";
        return result;
    }
    if (note.want_store) {
        result.code = "HELD";
        result.stored = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.stored = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
