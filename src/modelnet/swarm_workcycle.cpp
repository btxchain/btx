// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workcycle.h>

#include <string>

namespace modelnet {

SwarmWorkCycleResult SwarmNoteWorkCycle(const SwarmWorkCycle& cycle, std::string& err)
{
    SwarmWorkCycleResult result;
    result.advanced = false;
    if (cycle.cycle_id.empty()) {
        result.code = "CYCLE";
        result.advanced = false;
        err = "CYCLE";
        return result;
    }
    // FUNDING wins even when want_advance is true and even when another
    // flag is also false. Nothing is funded.
    if (!cycle.fund) {
        result.code = "FUNDING";
        result.advanced = false;
        err = "FUNDING";
        return result;
    }
    // INCOMPLETE wins even when want_advance is true.
    if (!cycle.publish || !cycle.lease || !cycle.pay || !cycle.frontier || !cycle.graduate) {
        result.code = "INCOMPLETE";
        result.advanced = false;
        err = "INCOMPLETE";
        return result;
    }
    // This note does not advance a cycle. Nothing is broadcast.
    if (cycle.want_advance) {
        result.code = "HELD";
        result.advanced = false;
        err.clear();
        return result;
    }
    result.code = "NOTED";
    result.advanced = false;
    err.clear();
    return result;
}

} // namespace modelnet
