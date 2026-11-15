// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_WORKLOAD_H
#define BTX_MODELNET_SWARM_WORKLOAD_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * A local workload. workload_id names the workload. durable_atoms is the
 * durable count. volatile_task is work that may be dropped. coordinator_gone
 * marks the coordinator as gone. want_commit asks this book to commit.
 *
 * A local workload keeps durable atoms and drops volatile work when the
 * coordinator is gone. It does not commit or move bytes.
 */
struct SwarmWorkload {
    std::string workload_id;
    int64_t durable_atoms{0};
    std::string volatile_task;
    bool coordinator_gone{false};
    bool want_commit{false};
};

/**
 * Outcome of applying a local workload. committed and bytes_moved stay false
 * on every path. durable_atoms is the copied durable count.
 *
 * A local workload keeps durable atoms and drops volatile work when the
 * coordinator is gone. It does not commit or move bytes.
 */
struct SwarmWorkloadResult {
    std::string code;
    bool committed{false};
    bool bytes_moved{false};
    int64_t durable_atoms{0};
    bool volatile_kept{false};
};

/**
 * Apply a local workload. Order, first match wins: an empty workload_id is
 * WORK and volatile_kept is false. If coordinator_gone is true, the result is
 * DURABLE even when want_commit is false, durable_atoms is unchanged, and
 * volatile_kept is false. want_commit is HELD and volatile_kept is true.
 * Otherwise the result is NOTED and err is cleared, with volatile_kept true.
 * committed and bytes_moved stay false on every path. durable_atoms is copied
 * into the result on every path, including zero.
 *
 * A local workload keeps durable atoms and drops volatile work when the
 * coordinator is gone. It does not commit or move bytes.
 */
SwarmWorkloadResult SwarmApplyWorkload(const SwarmWorkload& work, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_WORKLOAD_H
