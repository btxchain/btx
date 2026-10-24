// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoswarmdjoin2.h>

#include <string>

namespace modelnet {

SwarmNotNoSwarmdJoin2Result SwarmNoteNotNoSwarmdJoin2(const SwarmNotNoSwarmdJoin2& note, std::string& err)
{
    SwarmNotNoSwarmdJoin2Result result;
    result.launched = false;
    // A sidecar name on the join path launches nothing. The control plane stays inside btxd.
    if (note.name_id.empty()) {
        result.code = "NAME";
        result.launched = false;
        err = "NAME";
        return result;
    }
    if (note.sidecar) {
        result.code = "NOT_LAUNCHED";
        result.launched = false;
        err = "NOT_LAUNCHED";
        return result;
    }
    if (note.want_launch) {
        result.code = "HELD";
        result.launched = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
