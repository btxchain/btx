// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoguestagent2.h>

#include <string>

namespace modelnet {

SwarmNotNoGuestAgent2Result SwarmNoteNotNoGuestAgent2(const SwarmNotNoGuestAgent2& note, std::string& err)
{
    SwarmNotNoGuestAgent2Result result;
    result.passed = false;
    // A missing guest agent does not pass Windows.
    if (note.check_id.empty()) {
        result.code = "CHECK";
        result.passed = false;
        err = "CHECK";
        return result;
    }
    if (note.no_agent) {
        result.code = "NOT_PASSED";
        result.passed = false;
        err = "NOT_PASSED";
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
