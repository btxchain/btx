// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notkvpage.h>

#include <string>

namespace modelnet {

SwarmNotKvPageResult SwarmNoteNotKvPage(const SwarmNotKvPage& note, std::string& err)
{
    SwarmNotKvPageResult result;
    result.shared = false;
    result.bytes_moved = false;
    // Incompatible tensors do not share KV pages.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (!note.compatible) {
        result.code = "SEPARATE";
        result.shared = false;
        result.bytes_moved = false;
        err = "SEPARATE";
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
