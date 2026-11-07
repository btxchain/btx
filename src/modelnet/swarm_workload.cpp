// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_workload.h>

namespace modelnet {

SwarmWorkloadResult SwarmApplyWorkload(const SwarmWorkload& work, std::string& err)
{
    // A local workload keeps durable atoms and drops volatile work when the coordinator is gone. It does not commit or move bytes.
    SwarmWorkloadResult result;
    result.committed = false;
    result.bytes_moved = false;
    result.durable_atoms = work.durable_atoms;
    if (work.workload_id.empty()) {
        result.code = "WORK";
        result.committed = false;
        result.bytes_moved = false;
        result.durable_atoms = work.durable_atoms;
        result.volatile_kept = false;
        err = "WORK";
        return result;
    }
    if (work.coordinator_gone) {
        result.code = "DURABLE";
        result.committed = false;
        result.bytes_moved = false;
        result.durable_atoms = work.durable_atoms;
        result.volatile_kept = false;
        err = "DURABLE";
        return result;
    }
    if (work.want_commit) {
        result.code = "HELD";
        result.committed = false;
        result.bytes_moved = false;
        result.durable_atoms = work.durable_atoms;
        result.volatile_kept = true;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.committed = false;
    result.bytes_moved = false;
    result.durable_atoms = work.durable_atoms;
    result.volatile_kept = true;
    err.clear();
    return result;
}

} // namespace modelnet
