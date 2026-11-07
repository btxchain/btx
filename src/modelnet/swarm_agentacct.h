// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTACCT_H
#define BTX_MODELNET_SWARM_AGENTACCT_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Per-agent running thread and memory totals.
 *
 * Charge rejects an empty agent (AGENT). Negative threads or memory
 * is RANGE and adds nothing. A charge that would put that agent's
 * thread total above 64, or its memory total above 16384 MiB, is
 * CAPPED and adds nothing. The previous totals stay. Otherwise both
 * totals increase and err is cleared.
 * Threads and Memory report the agent's current totals, or 0 when
 * the agent has none.
 * Release rejects a negative amount, or an amount above the current
 * total on either side (RANGE), and leaves both totals unchanged.
 * Otherwise both totals decrease and err is cleared.
 * Caps apply to each agent on its own.
 */
class SwarmAgentAcct {
public:
    bool Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);
    int64_t Threads(const std::string& agent) const;
    int64_t Memory(const std::string& agent) const;
    bool Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);

private:
    static constexpr int64_t THREAD_CAP = 64;
    static constexpr int64_t MEMORY_CAP_MIB = 16384;

    struct Usage {
        int64_t threads{0};
        int64_t memory_mib{0};
    };

    std::map<std::string, Usage> m_usage;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTACCT_H
