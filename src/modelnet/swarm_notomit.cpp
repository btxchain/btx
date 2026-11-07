// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notomit.h>

namespace modelnet {

SwarmNotOmitResult SwarmNoteNotOmit(const SwarmNotOmit& note, std::string& err)
{
    SwarmNotOmitResult result;
    result.omitted = false;
    if (note.target_id.empty()) {
        result.code = "TARGET";
        result.omitted = false;
        err = "TARGET";
        return result;
    }
    // The default build must not silently omit the core swarm lifecycle.
    if (note.default_build && note.want_omit) {
        result.code = "PRESENT";
        result.omitted = false;
        err = "PRESENT";
        return result;
    }
    result.code = "NOTED";
    result.omitted = false;
    err.clear();
    return result;
}

} // namespace modelnet
