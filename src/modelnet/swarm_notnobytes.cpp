// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobytes.h>

#include <string>

namespace modelnet {

SwarmNotNoBytesResult SwarmNoteNotNoBytes(const SwarmNotNoBytes& note, std::string& err)
{
    SwarmNotNoBytesResult result;
    result.published = false;
    result.bytes = 0;
    if (note.transfer_id.empty()) {
        result.code = "TRANSFER";
        result.published = false;
        result.bytes = 0;
        err = "TRANSFER";
        return result;
    }
    // No transferred-byte count is published by this note.
    if (note.want_publish) {
        result.code = "UNMEASURED";
        result.published = false;
        result.bytes = 0;
        err = "UNMEASURED";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes = 0;
    err.clear();
    return result;
}

} // namespace modelnet
