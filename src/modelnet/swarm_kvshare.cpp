// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvshare.h>

namespace modelnet {

SwarmKvShareResult SwarmNoteKvShare(const SwarmKvShare& share, std::string& err)
{
    SwarmKvShareResult result;
    result.shared = false;
    result.bytes_moved = false;
    if (share.page_id.empty()) {
        result.code = "KV";
        result.shared = false;
        result.bytes_moved = false;
        err = "KV";
        return result;
    }
    // Incompatible tensors do not share a KV page.
    // This wins even when want_share is true.
    if (!share.same_fingerprint || !share.compatible) {
        result.code = "INCOMPATIBLE";
        result.shared = false;
        result.bytes_moved = false;
        err = "INCOMPATIBLE";
        return result;
    }
    // A matching page still moves no bytes in this note.
    if (share.want_share) {
        result.code = "HELD";
        result.shared = false;
        result.bytes_moved = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.shared = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
