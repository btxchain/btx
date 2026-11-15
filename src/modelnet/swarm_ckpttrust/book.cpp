// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/book.h>

#include <modelnet/swarm_ckpttrust/limits.h>

#include <utility>

namespace modelnet {

bool SwarmCheckpointTrustBook::contains(const std::string& claim) const
{
    if (claim.empty()) return false;
    return m_claims.find(claim) != m_claims.end();
}

std::string SwarmCheckpointTrustBook::claim_of(const std::string& claim) const
{
    const auto found = m_claims.find(claim);
    if (found == m_claims.end()) return {};
    return found->second.claim();
}

std::size_t SwarmCheckpointTrustBook::size() const
{
    return m_claims.size();
}

bool SwarmCheckpointTrustBook::trusted() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.trusted()) return true;
    }
    return kSwarmCheckpointTrustTrusted;
}

int64_t SwarmCheckpointTrustBook::bytes_moved() const
{
    int64_t total = kSwarmCheckpointTrustBytesMoved;
    for (const auto& entry : m_claims) {
        total += entry.second.bytes_moved();
    }
    return total;
}

bool SwarmCheckpointTrustBook::gpu() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.gpu()) return true;
    }
    return kSwarmCheckpointTrustGpu;
}

bool SwarmCheckpointTrustBook::launched() const
{
    for (const auto& entry : m_claims) {
        if (entry.second.launched()) return true;
    }
    return kSwarmCheckpointTrustLaunched;
}

bool SwarmCheckpointTrustBook::store(const std::string& claim)
{
    if (contains(claim)) return false;
    SwarmCheckpointTrustRecord record = SwarmCheckpointTrustRecord::Make(claim);
    if (!SwarmCheckpointTrustRecordUsable(record)) return false;
    m_claims.emplace(claim, std::move(record));
    return true;
}

} // namespace modelnet
