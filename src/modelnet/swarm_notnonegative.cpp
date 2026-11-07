// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnonegative.h>

#include <string>

namespace modelnet {

SwarmNotNoNegativeResult SwarmNoteNotNoNegative(const SwarmNotNoNegative& note, std::string& err)
{
    SwarmNotNoNegativeResult result;
    result.dropped = false;
    result.trained = false;
    // dropped and trained stay false on every path. A negative result
    // stays on record and is not dropped.
    if (note.result_id.empty()) {
        result.code = "RESULT";
        result.dropped = false;
        result.trained = false;
        err = "RESULT";
        return result;
    }
    if (note.negative) {
        result.code = "KEPT";
        result.dropped = false;
        result.trained = false;
        err = "KEPT";
        return result;
    }
    if (note.want_drop) {
        result.code = "KEPT";
        result.dropped = false;
        result.trained = false;
        err = "KEPT";
        return result;
    }
    result.code = "NOTED";
    result.dropped = false;
    result.trained = false;
    err.clear();
    return result;
}

} // namespace modelnet
