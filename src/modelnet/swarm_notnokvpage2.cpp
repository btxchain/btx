// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnokvpage2.h>

#include <string>

namespace modelnet {

SwarmNotNoKvPage2Result SwarmNoteNotNoKvPage2(const SwarmNotNoKvPage2& note, std::string& err)
{
    SwarmNotNoKvPage2Result result;
    result.shared = false;
    result.bytes_moved = false;
    // Incompatible tensors do not share a KV page.
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
