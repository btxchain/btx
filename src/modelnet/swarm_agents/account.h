// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_ACCOUNT_H
#define BTX_MODELNET_SWARM_AGENTS_ACCOUNT_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Per-agent running thread and memory totals.
 *
 * Charge rejects an empty agent (AGENT). A negative amount is RANGE
 * and adds nothing. A charge that would put that agent's thread total
 * above 64, or its memory total above 16384 MiB, is CAPPED and adds
 * nothing. The previous totals stay. Otherwise both totals increase.
 * Release rejects a negative amount, or an amount above the current
 * total on either side (RANGE), and leaves both totals unchanged.
 * Caps apply to each agent on its own.
 */
class SwarmAgentAccount {
public:
    bool Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);
    bool Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err);
    int64_t Threads(const std::string& agent) const;
    int64_t Memory(const std::string& agent) const;

private:
    struct Usage {
        int64_t threads{0};
        int64_t memory_mib{0};
    };

    std::map<std::string, Usage> m_usage;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_ACCOUNT_H
