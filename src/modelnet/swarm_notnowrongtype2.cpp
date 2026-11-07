// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowrongtype2.h>

#include <string>

namespace modelnet {

SwarmNotNoWrongType2Result SwarmNoteNotNoWrongType2(const SwarmNotNoWrongType2& note, std::string& err)
{
    SwarmNotNoWrongType2Result result;
    result.scanned = false;
    // A wrong-type field aborts a scan.
    if (note.field_id.empty()) {
        result.code = "FIELD";
        result.scanned = false;
        err = "FIELD";
        return result;
    }
    if (note.wrong_type) {
        result.code = "ABORT";
        result.scanned = false;
        err = "ABORT";
        return result;
    }
    if (note.want_scan) {
        result.code = "HELD";
        result.scanned = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.scanned = false;
    err.clear();
    return result;
}

} // namespace modelnet
