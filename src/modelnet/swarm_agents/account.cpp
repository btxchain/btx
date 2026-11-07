// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/account.h>

#include <modelnet/swarm_agents/codes.h>
#include <modelnet/swarm_agents/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmAgentAccount::Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    if (agent.empty()) {
        err = kAgentAgent;
        return false;
    }
    if (threads < 0 || memory_mib < 0) {
        err = kAgentRange;
        return false;
    }
    const auto it = m_usage.find(agent);
    const int64_t held_threads = it == m_usage.end() ? 0 : it->second.threads;
    const int64_t held_memory = it == m_usage.end() ? 0 : it->second.memory_mib;
    if (threads > kAgentThreadCap - held_threads || memory_mib > kAgentMemoryCapMib - held_memory) {
        err = kAgentCapped;
        return false;
    }
    Usage& usage = m_usage[agent];
    usage.threads += threads;
    usage.memory_mib += memory_mib;
    err.clear();
    return true;
}

bool SwarmAgentAccount::Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    if (threads < 0 || memory_mib < 0) {
        err = kAgentRange;
        return false;
    }
    const auto it = m_usage.find(agent);
    const int64_t held_threads = it == m_usage.end() ? 0 : it->second.threads;
    const int64_t held_memory = it == m_usage.end() ? 0 : it->second.memory_mib;
    if (threads > held_threads || memory_mib > held_memory) {
        err = kAgentRange;
        return false;
    }
    if (it == m_usage.end()) {
        err.clear();
        return true;
    }
    Usage& usage = m_usage[agent];
    usage.threads -= threads;
    usage.memory_mib -= memory_mib;
    err.clear();
    return true;
}

int64_t SwarmAgentAccount::Threads(const std::string& agent) const
{
    const auto it = m_usage.find(agent);
    if (it == m_usage.end()) {
        return 0;
    }
    return it->second.threads;
}

int64_t SwarmAgentAccount::Memory(const std::string& agent) const
{
    const auto it = m_usage.find(agent);
    if (it == m_usage.end()) {
        return 0;
    }
    return it->second.memory_mib;
}

} // namespace modelnet
