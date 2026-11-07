// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTRUN_LEASE_H
#define BITCOIN_MODELNET_SWARM_AGENTRUN_LEASE_H

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

class SwarmAgentRunTasks;
class SwarmAgentRunTrace;

/**
 * One stored lease. The fence for Assign is worker plus epoch.
 * until_ms and now_ms are the bounds checked at insert. A stored lease
 * is not removed when the clock would pass until_ms later.
 */
struct SwarmAgentRunLease {
    std::string worker;
    int64_t epoch{0};
    int64_t until_ms{0};
    int64_t now_ms{0};
};

/**
 * Leases keyed by task.
 * Unknown task is TASK. Empty worker is WORKER. Epoch below 0 is EPOCH.
 * now_ms >= until_ms, including equality, is EXPIRED and stores nothing.
 * Those checks run before the duplicate check. A second valid lease for
 * the same task is REPLAY and keeps the first fence.
 */
class SwarmAgentRunLeases {
public:
    bool Lease(const SwarmAgentRunTasks& tasks, const std::string& task, const std::string& worker, int64_t epoch,
               int64_t until_ms, int64_t now_ms, SwarmAgentRunTrace& trace, std::string& err);

    bool leased(const std::string& task) const;
    bool any() const;
    bool matches(const std::string& task, const std::string& worker, int64_t epoch) const;
    std::string worker(const std::string& task) const;
    int64_t epoch(const std::string& task) const;
    int64_t until_ms(const std::string& task) const;
    int64_t now_ms(const std::string& task) const;
    std::size_t count() const;

private:
    std::map<std::string, SwarmAgentRunLease> m_leases;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTRUN_LEASE_H
