// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notbytes.h>

#include <string>

namespace modelnet {

SwarmNotBytesResult SwarmNoteNotBytes(const SwarmNotBytes& note, std::string& err)
{
    SwarmNotBytesResult result;
    result.published = false;
    result.bytes_moved = false;
    if (note.page_id.empty()) {
        result.code = "BYTES";
        result.published = false;
        result.bytes_moved = false;
        err = "BYTES";
        return result;
    }
    // No transferred-byte count has been measured, so this note does not publish one.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.bytes_moved = false;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
