// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notdiscover.h>

#include <string>

namespace modelnet {

SwarmNotDiscoverResult SwarmNoteNotDiscover(const SwarmNotDiscover& note, std::string& err)
{
    SwarmNotDiscoverResult result;
    result.discovered = false;
    result.launched = false;
    // This note does not scan for a runtime or launch one.
    if (note.runtime_id.empty()) {
        result.code = "RUNTIME";
        result.discovered = false;
        result.launched = false;
        err = "RUNTIME";
        return result;
    }
    if (note.want_discover) {
        result.code = "NOT_FOUND";
        result.discovered = false;
        result.launched = false;
        err = "NOT_FOUND";
        return result;
    }
    result.code = "NOTED";
    result.discovered = false;
    result.launched = false;
    err.clear();
    return result;
}

} // namespace modelnet
