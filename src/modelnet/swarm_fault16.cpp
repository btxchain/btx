// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault16.h>

#include <string>

namespace modelnet {

SwarmFault16Result SwarmRecoverFault16(const SwarmFault16& in, std::string& err)
{
    SwarmFault16Result out;
    // Two pools cannot reserve the same collateral. Nothing is reserved,
    // broadcast, or committed.
    out.reserved = false;
    out.broadcast = false;
    out.committed = false;
    if (in.pool_a.empty() || in.pool_b.empty() || in.collateral_id.empty()) {
        out.code = "POOL";
        out.reserved = false;
        out.broadcast = false;
        out.committed = false;
        err = "POOL";
        return out;
    }
    if (in.pool_a == in.pool_b || in.same_collateral) {
        out.code = "COLLATERAL_REUSE";
        out.reserved = false;
        out.broadcast = false;
        out.committed = false;
        err = "COLLATERAL_REUSE";
        return out;
    }
    if (in.want_reserve) {
        out.code = "HELD";
        out.reserved = false;
        out.broadcast = false;
        out.committed = false;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    out.reserved = false;
    out.broadcast = false;
    out.committed = false;
    err.clear();
    return out;
}

} // namespace modelnet
