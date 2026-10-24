// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault09.h>

#include <string>

namespace modelnet {

SwarmFault09Result SwarmRecoverFault09(const SwarmFault09& in, std::string& err)
{
    SwarmFault09Result out;
    // A partial transfer is never accepted. Nothing is moved, committed, or broadcast.
    out.accepted = false;
    out.bytes_moved = false;
    out.committed = false;
    out.broadcast = false;
    if (in.artifact_id.empty()) {
        out.code = "ARTIFACT";
        out.accepted = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "ARTIFACT";
        return out;
    }
    if (!in.complete) {
        // Incomplete stays incomplete even when the caller wants accept.
        out.code = "INCOMPLETE";
        out.accepted = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "INCOMPLETE";
        return out;
    }
    if (in.want_accept) {
        out.code = "HELD";
        out.accepted = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.accepted = false;
    out.bytes_moved = false;
    out.committed = false;
    out.broadcast = false;
    err.clear();
    return out;
}

} // namespace modelnet
