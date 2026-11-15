// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowinlife2.h>

namespace modelnet {

SwarmNotNoWinLife2Result SwarmNoteNotNoWinLife2(const SwarmNotNoWinLife2& note, std::string& err)
{
    SwarmNotNoWinLife2Result result;
    result.passed = false;
    // A unit note does not pass a Windows lifecycle.
    if (note.check_id.empty()) {
        result.code = "CHECK";
        result.passed = false;
        err = "CHECK";
        return result;
    }
    if (note.want_pass) {
        result.code = "HELD";
        result.passed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
