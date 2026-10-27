// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoleak.h>

#include <string>

namespace modelnet {

SwarmNotNoLeakResult SwarmNoteNotNoLeak(const SwarmNotNoLeak& note, std::string& err)
{
    SwarmNotNoLeakResult result;
    result.exported = false;
    result.bytes_moved = false;
    if (note.update_id.empty()) {
        result.code = "UPDATE";
        result.exported = false;
        result.bytes_moved = false;
        err = "UPDATE";
        return result;
    }
    // A gradient update is not exported and moves no bytes.
    if (note.want_export) {
        result.code = "NOT_EXPORTED";
        result.exported = false;
        result.bytes_moved = false;
        err = "NOT_EXPORTED";
        return result;
    }
    result.code = "NOTED";
    result.exported = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
