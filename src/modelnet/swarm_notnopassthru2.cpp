// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnopassthru2.h>

#include <string>

namespace modelnet {

SwarmNotNoPassThru2Result SwarmNoteNotNoPassThru2(const SwarmNotNoPassThru2& note, std::string& err)
{
    SwarmNotNoPassThru2Result result;
    result.started = false;
    // GPU passthrough is not started.
    if (note.check_id.empty()) {
        result.code = "CHECK";
        result.started = false;
        err = "CHECK";
        return result;
    }
    if (note.passthrough) {
        result.code = "NOT_STARTED";
        result.started = false;
        err = "NOT_STARTED";
        return result;
    }
    if (note.want_start) {
        result.code = "HELD";
        result.started = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.started = false;
    err.clear();
    return result;
}

} // namespace modelnet
