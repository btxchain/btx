// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnobytespub2.h>

#include <string>

namespace modelnet {

SwarmNotNoBytesPub2Result SwarmNoteNotNoBytesPub2(const SwarmNotNoBytesPub2& note, std::string& err)
{
    SwarmNotNoBytesPub2Result result;
    result.published = false;
    result.bytes_moved = false;
    // This note publishes no transferred-byte count and moves no bytes.
    if (note.sample_id.empty()) {
        result.code = "SAMPLE";
        result.published = false;
        result.bytes_moved = false;
        err = "SAMPLE";
        return result;
    }
    if (note.want_publish) {
        result.code = "HELD";
        result.published = false;
        result.bytes_moved = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.published = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
