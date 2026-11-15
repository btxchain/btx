// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notwindows.h>

#include <string>

namespace modelnet {

SwarmNotWindowsResult SwarmNoteNotWindows(const SwarmNotWindows& note, std::string& err)
{
    SwarmNotWindowsResult result;
    result.passed = false;
    // A Windows guest that has not run a BTX binary is not a pass.
    if (note.node_id.empty()) {
        result.code = "WINDOWS";
        result.passed = false;
        err = "WINDOWS";
        return result;
    }
    if (note.want_pass) {
        result.code = "UNQUALIFIED";
        result.passed = false;
        err = "UNQUALIFIED";
        return result;
    }
    result.code = "NOTED";
    result.passed = false;
    err.clear();
    return result;
}

} // namespace modelnet
