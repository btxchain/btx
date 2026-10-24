// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_governor.h>

#include <cstdint>

namespace modelnet {

SwarmGovernorResult SwarmNoteGovernor(const SwarmGovernor& governor, std::string& err)
{
    SwarmGovernorResult result;
    result.workers_running = 0;
    if (governor.node_id.empty() || governor.requested_workers < 0) {
        result.code = "GOVERNOR";
        result.workers_running = 0;
        err = "GOVERNOR";
        return result;
    }
    // Any one of idle_off, battery, thermal, or metered drains workers
    // to zero. Nothing is launched.
    if (governor.idle_off || governor.battery || governor.thermal || governor.metered) {
        result.code = "DRAIN";
        result.workers_running = 0;
        err = "DRAIN";
        return result;
    }
    // This note does not start workers.
    if (governor.requested_workers > 0) {
        result.code = "HELD";
        result.workers_running = 0;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.workers_running = 0;
    err.clear();
    return result;
}

} // namespace modelnet
