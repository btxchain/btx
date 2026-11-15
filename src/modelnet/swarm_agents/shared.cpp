// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agents/shared.h>

#include <modelnet/swarm_agents/codes.h>

#include <string>
#include <utility>

namespace modelnet {

bool SwarmAgentSharedResult::Publish(const std::string& key, const std::string& hash, std::string& err)
{
    if (key.empty() || hash.empty()) {
        err = kAgentHash;
        return false;
    }
    const auto it = m_hash.find(key);
    if (it == m_hash.end()) {
        m_hash.emplace(key, hash);
        err.clear();
        return true;
    }
    if (it->second == hash) {
        err.clear();
        return true;
    }
    err = kAgentConflict;
    return false;
}

bool SwarmAgentSharedResult::Attach(const std::string& consumer, const std::string& key, const std::string& hash, std::string& err)
{
    if (consumer.empty()) {
        err = kAgentConsumer;
        return false;
    }
    if (key.empty() || hash.empty()) {
        err = kAgentHash;
        return false;
    }
    const auto it = m_hash.find(key);
    if (it == m_hash.end() || it->second != hash) {
        err = kAgentConflict;
        return false;
    }
    m_consumers.insert(std::make_pair(consumer, key));
    err.clear();
    return true;
}

std::string SwarmAgentSharedResult::Shared(const std::string& key) const
{
    const auto it = m_hash.find(key);
    if (it == m_hash.end()) {
        return std::string();
    }
    return it->second;
}

bool SwarmAgentSharedResult::attached(const std::string& consumer, const std::string& key) const
{
    return m_consumers.find(std::make_pair(consumer, key)) != m_consumers.end();
}

} // namespace modelnet
