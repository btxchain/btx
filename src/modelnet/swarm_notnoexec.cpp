// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoexec.h>

#include <string>

namespace modelnet {

SwarmNotNoExecResult SwarmNoteNotNoExec(const SwarmNotNoExec& note, std::string& err)
{
    SwarmNotNoExecResult result;
    result.launched = false;
    result.bytes_moved = false;
    // This note launches no process.
    if (note.sandbox_id.empty()) {
        result.code = "SANDBOX";
        result.launched = false;
        result.bytes_moved = false;
        err = "SANDBOX";
        return result;
    }
    if (note.want_exec) {
        result.code = "NOT_LAUNCHED";
        result.launched = false;
        result.bytes_moved = false;
        err = "NOT_LAUNCHED";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    result.bytes_moved = false;
    err.clear();
    return result;
}

} // namespace modelnet
