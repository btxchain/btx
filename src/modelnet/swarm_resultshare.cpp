// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_resultshare.h>

namespace modelnet {

bool SwarmResultShare::Publish(const std::string& result_id, const std::string& hash, std::string& err)
{
    if (result_id.empty() || hash.empty()) {
        err = "RESULT";
        return false;
    }
    if (m_shares.find(result_id) != m_shares.end()) {
        err = "REPLAY";
        return false;
    }
    Share stored;
    stored.hash = hash;
    m_shares.emplace(result_id, std::move(stored));
    err.clear();
    return true;
}

bool SwarmResultShare::Attach(const std::string& result_id, const std::string& consumer, const std::string& hash,
                              std::string& err)
{
    const auto it = m_shares.find(result_id);
    if (it == m_shares.end()) {
        err = "RESULT";
        return false;
    }
    if (consumer.empty()) {
        err = "CONSUMER";
        return false;
    }
    if (hash != it->second.hash) {
        err = "CONFLICT";
        return false;
    }
    if (it->second.consumers.find(consumer) != it->second.consumers.end()) {
        err = "REPLAY";
        return false;
    }
    it->second.consumers.insert(consumer);
    err.clear();
    return true;
}

bool SwarmResultShare::Attached(const std::string& result_id, const std::string& consumer) const
{
    const auto it = m_shares.find(result_id);
    if (it == m_shares.end()) return false;
    return it->second.consumers.find(consumer) != it->second.consumers.end();
}

} // namespace modelnet
