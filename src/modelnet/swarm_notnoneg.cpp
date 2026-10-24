// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoneg.h>

#include <string>

namespace modelnet {

SwarmNotNoNegResult SwarmNoteNotNoNeg(const SwarmNotNoNeg& note, std::string& err)
{
    SwarmNotNoNegResult result;
    result.dropped = false;
    result.bytes_moved = false;
    // dropped and bytes_moved stay false on every path. A negative
    // result stays and is not dropped.
    if (note.result_id.empty()) {
        result.code = "RESULT";
        result.dropped = false;
        result.bytes_moved = false;
        err = "RESULT";
        return result;
    }
    if (note.negative) {
        result.code = "KEPT";
        result.dropped = false;
        result.bytes_moved = false;
        err = "KEPT";
        return result;
    }
    if (note.want_drop) {
        result.code = "KEPT";
        result.dropped = false;
        result.bytes_moved = false;
        err = "KEPT";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
