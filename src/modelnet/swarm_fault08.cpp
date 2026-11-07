// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault08.h>

#include <string>

namespace modelnet {

SwarmFault08Result SwarmRecoverFault08(const SwarmFault08& in, std::string& err)
{
    SwarmFault08Result out;
    // A truncated or incompatible cache is never accepted, moved, committed, or broadcast.
    out.accepted = false;
    out.bytes_moved = false;
    out.committed = false;
    out.broadcast = false;
    if (in.page_id.empty()) {
        out.code = "PAGE";
        out.accepted = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "PAGE";
        return out;
    }
    if (in.truncated || !in.compatible) {
        // Truncated wins even if want_accept is set.
        out.code = "PREFIX_MISMATCH";
        out.accepted = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "PREFIX_MISMATCH";
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
