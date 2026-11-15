// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosideexec2.h>

#include <string>

namespace modelnet {

SwarmNotNoSideExec2Result SwarmNoteNotNoSideExec2(const SwarmNotNoSideExec2& note, std::string& err)
{
    SwarmNotNoSideExec2Result result;
    result.executed = false;
    // btxd does not exec a sidecar.
    if (note.name_id.empty()) {
        result.code = "NAME";
        result.executed = false;
        err = "NAME";
        return result;
    }
    if (note.want_exec) {
        result.code = "HELD";
        result.executed = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.executed = false;
    err.clear();
    return result;
}

} // namespace modelnet
