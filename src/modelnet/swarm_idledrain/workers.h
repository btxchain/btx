// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_IDLEDRAIN_WORKERS_H
#define BITCOIN_MODELNET_SWARM_IDLEDRAIN_WORKERS_H

#include <cstdint>

namespace modelnet {

/**
 * Worker count for one idle-drain plane.
 * start assigns the open count. increment adds one and will not pass
 * the cap. zero stores none. The drain latch lives with the caller.
 */
class SwarmIdleDrainWorkers {
public:
    int64_t count() const { return m_count; }

    void start();
    void increment();
    void zero();

private:
    int64_t m_count{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_IDLEDRAIN_WORKERS_H
