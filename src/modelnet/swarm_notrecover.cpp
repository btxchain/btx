// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrecover.h>

#include <string>

namespace modelnet {

SwarmNotRecoverResult SwarmNoteNotRecover(const SwarmNotRecover& note, std::string& err)
{
    SwarmNotRecoverResult result;
    result.continued = false;
    // A surviving node has not continued after the coordinator process was terminated.
    if (note.node_id.empty()) {
        result.code = "NODE";
        result.continued = false;
        err = "NODE";
        return result;
    }
    if (note.want_continue) {
        result.code = "NOT_CONTINUED";
        result.continued = false;
        err = "NOT_CONTINUED";
        return result;
    }
    result.code = "NOTED";
    result.continued = false;
    err.clear();
    return result;
}

} // namespace modelnet
