// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowin.h>

namespace modelnet {

SwarmNotNoWinResult SwarmNoteNotNoWin(const SwarmNotNoWin& note, std::string& err)
{
    SwarmNotNoWinResult result;
    result.passed = false;
    result.guest_agent = false;
    if (note.host_id.empty()) {
        result.code = "HOST";
        result.passed = false;
        result.guest_agent = false;
        err = "HOST";
        return result;
    }
    // A Windows claim is unqualified. This note does not mark a platform passed.
    if (note.want_pass) {
        result.code = "UNQUALIFIED";
        result.passed = false;
        result.guest_agent = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    result.guest_agent = false;
    err.clear();
    return result;
}

} // namespace modelnet
