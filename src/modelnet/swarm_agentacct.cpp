// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentacct.h>

namespace modelnet {

bool SwarmAgentAcct::Charge(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    if (agent.empty()) {
        err = "AGENT";
        return false;
    }
    if (threads < 0 || memory_mib < 0) {
        err = "RANGE";
        return false;
    }
    const auto it = m_usage.find(agent);
    const int64_t held_threads = it == m_usage.end() ? 0 : it->second.threads;
    const int64_t held_memory = it == m_usage.end() ? 0 : it->second.memory_mib;
    if (threads > THREAD_CAP - held_threads || memory_mib > MEMORY_CAP_MIB - held_memory) {
        err = "CAPPED";
        return false;
    }
    Usage& usage = m_usage[agent];
    usage.threads += threads;
    usage.memory_mib += memory_mib;
    err.clear();
    return true;
}

int64_t SwarmAgentAcct::Threads(const std::string& agent) const
{
    const auto it = m_usage.find(agent);
    if (it == m_usage.end()) return 0;
    return it->second.threads;
}

int64_t SwarmAgentAcct::Memory(const std::string& agent) const
{
    const auto it = m_usage.find(agent);
    if (it == m_usage.end()) return 0;
    return it->second.memory_mib;
}

bool SwarmAgentAcct::Release(const std::string& agent, int64_t threads, int64_t memory_mib, std::string& err)
{
    if (threads < 0 || memory_mib < 0) {
        err = "RANGE";
        return false;
    }
    const auto it = m_usage.find(agent);
    const int64_t held_threads = it == m_usage.end() ? 0 : it->second.threads;
    const int64_t held_memory = it == m_usage.end() ? 0 : it->second.memory_mib;
    if (threads > held_threads || memory_mib > held_memory) {
        err = "RANGE";
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

} // namespace modelnet
