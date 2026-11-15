// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfailover.h>

namespace modelnet {

SwarmNotFailoverResult SwarmNoteNotFailover(const SwarmNotFailover& note, std::string& err)
{
    // published, failover_ms, and continued stay false/zero on every branch.
    // This note does not claim a process was killed.
    SwarmNotFailoverResult out;
    out.published = false;
    out.failover_ms = 0;
    out.continued = false;

    if (note.coord_id.empty()) {
        out.code = "COORD";
        err = "COORD";
        return out;
    }
    if (note.want_publish) {
        out.code = "UNMEASURED";
        err = "UNMEASURED";
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
