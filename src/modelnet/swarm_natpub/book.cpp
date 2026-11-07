// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/book.h>

#include <modelnet/swarm_natpub/limits.h>

#include <utility>

namespace modelnet {

bool SwarmNatPubBook::contains(const std::string& endpoint) const
{
    if (endpoint.empty()) return false;
    return m_claims.find(endpoint) != m_claims.end();
}

std::string SwarmNatPubBook::endpoint_of(const std::string& endpoint) const
{
    const auto found = m_claims.find(endpoint);
    if (found == m_claims.end()) return {};
    return found->second.endpoint();
}

std::size_t SwarmNatPubBook::size() const
{
    return m_claims.size();
}

bool SwarmNatPubBook::published() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.published()) return true;
    }
    return kSwarmNatPubPublished;
}

bool SwarmNatPubBook::published_of(const std::string& endpoint) const
{
    const auto found = m_claims.find(endpoint);
    if (found == m_claims.end()) return kSwarmNatPubPublished;
    return found->second.published();
}

int64_t SwarmNatPubBook::bytes_moved() const
{
    int64_t total = kSwarmNatPubBytesMoved;
    for (const auto& entry : m_claims) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmNatPubBook::connected() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.connected()) return true;
    }
    return kSwarmNatPubConnected;
}

bool SwarmNatPubBook::connected_of(const std::string& endpoint) const
{
    const auto found = m_claims.find(endpoint);
    if (found == m_claims.end()) return kSwarmNatPubConnected;
    return found->second.connected();
}

bool SwarmNatPubBook::launched() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.launched()) return true;
    }
    return kSwarmNatPubLaunched;
}

bool SwarmNatPubBook::store(const std::string& endpoint)
{
    if (contains(endpoint)) return false;
    SwarmNatPubRecord record = SwarmNatPubRecord::Make(endpoint);
    if (!SwarmNatPubRecordUsable(record)) return false;
    if (record.endpoint() != endpoint) return false;
    m_claims.emplace(endpoint, std::move(record));
    return true;
}

} // namespace modelnet
