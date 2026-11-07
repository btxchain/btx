// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnotype.h>

#include <string>

namespace modelnet {

SwarmNotNoTypeResult SwarmNoteNotNoType(const SwarmNotNoType& note, std::string& err)
{
    SwarmNotNoTypeResult result;
    result.scanned = false;
    result.bytes_moved = false;
    // A stored field of the wrong type aborts a scan, and this note moves no bytes.
    if (note.field_id.empty()) {
        result.code = "FIELD";
        result.scanned = false;
        result.bytes_moved = false;
        err = "FIELD";
        return result;
    }
    if (note.wrong_type) {
        result.code = "ABORT";
        result.scanned = false;
        result.bytes_moved = false;
        err = "ABORT";
        return result;
    }
    if (note.want_scan) {
        result.code = "ABORT";
        result.scanned = false;
        result.bytes_moved = false;
        err = "ABORT";
        return result;
    }
    result.code = "NOTED";
    result.scanned = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
