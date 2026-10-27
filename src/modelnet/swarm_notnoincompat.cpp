// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoincompat.h>

#include <string>

namespace modelnet {

SwarmNotNoIncompatResult SwarmNoteNotNoIncompat(const SwarmNotNoIncompat& note, std::string& err)
{
    SwarmNotNoIncompatResult result;
    result.shared = false;
    result.bytes_moved = false;
    // Incompatible tensors do not share KV pages and this note moves no bytes.
    if (note.tensor_id.empty()) {
        result.code = "TENSOR";
        result.shared = false;
        result.bytes_moved = false;
        err = "TENSOR";
        return result;
    }
    if (!note.compatible) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    if (note.want_share) {
        result.code = "NOT_SHARED";
        result.shared = false;
        result.bytes_moved = false;
        err = "NOT_SHARED";
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
