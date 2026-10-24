// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoresourcecap2.h>

namespace modelnet {

SwarmNotNoResourceCap2Result SwarmNoteNotNoResourceCap2(const SwarmNotNoResourceCap2& note, std::string& err)
{
    // A sandbox raise stays capped.
    SwarmNotNoResourceCap2Result result;
    result.raised = false;
    if (note.sandbox_id.empty()) {
        result.code = "SANDBOX";
        err = "SANDBOX";
        return result;
    }
    if (note.over_cap) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    if (note.want_raise) {
        result.code = "CAPPED";
        err = "CAPPED";
        return result;
    }
    result.code = "NOTED";
    err.clear();
    return result;
}

} // namespace modelnet
