// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault07.h>

#include <string>

namespace modelnet {

SwarmFault07Result SwarmRecoverFault07(const SwarmFault07& in, std::string& err)
{
    SwarmFault07Result out;
    // Local recovery only. bytes_moved, committed, and broadcast stay false.
    if (in.page_id.empty()) {
        out.code = "PAGE";
        out.recovered = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "PAGE";
        return out;
    }
    if (!in.owner_present) {
        out.code = "INCOMPLETE";
        out.recovered = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err = "INCOMPLETE";
        return out;
    }
    if (in.want_transfer) {
        out.code = "HELD";
        out.recovered = false;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    if (in.durable) {
        out.code = "DURABLE";
        out.recovered = true;
        out.bytes_moved = false;
        out.committed = false;
        out.broadcast = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.recovered = false;
    out.bytes_moved = false;
    out.committed = false;
    out.broadcast = false;
    err.clear();
    return out;
}

} // namespace modelnet
