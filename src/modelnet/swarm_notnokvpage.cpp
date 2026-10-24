// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokvpage.h>

#include <string>

namespace modelnet {

SwarmNotNoKvPageResult SwarmNoteNotNoKvPage(const SwarmNotNoKvPage& note, std::string& err)
{
    SwarmNotNoKvPageResult result;
    result.shared = false;
    result.bytes_moved = false;
    // Incompatible tensors share no KV page and move no bytes.
    if (note.page_id.empty()) {
        result.code = "PAGE";
        result.shared = false;
        result.bytes_moved = false;
        err = "PAGE";
        return result;
    }
    if (note.incompatible) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
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
