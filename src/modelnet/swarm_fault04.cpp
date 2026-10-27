// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault04.h>

namespace modelnet {

SwarmFault04Result SwarmRecoverFault04(const SwarmFault04& in, std::string& err)
{
    // Publication never happens. These flags stay false on every branch.
    // Nothing here claims a GPU ran.
    SwarmFault04Result out;
    out.published = false;
    out.recovered = false;
    out.distributed = false;
    out.bytes_moved = false;
    out.broadcast = false;

    if (in.job_id.empty()) {
        out.code = "JOB";
        err = "JOB";
        return out;
    }
    if (!in.checkpoint_saved) {
        out.code = "NO_CHECKPOINT";
        err = "NO_CHECKPOINT";
        return out;
    }
    if (in.want_publish) {
        out.code = "HELD";
        err.clear();
        return out;
    }
    if (in.durable) {
        out.code = "DURABLE";
        out.recovered = true;
        err.clear();
        return out;
    }
    out.code = "NOTED";
    err.clear();
    return out;
}

} // namespace modelnet
