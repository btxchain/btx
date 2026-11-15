// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckpttrust/swarm_ckpttrust.h>

#include <modelnet/swarm_ckpttrust/keep.h>
#include <modelnet/swarm_ckpttrust/limits.h>
#include <modelnet/swarm_ckpttrust/request.h>

namespace modelnet {

bool SwarmCheckpointTrust::Trust(const std::string& claim, std::string& err)
{
    return SwarmCheckpointTrustRequest{}.Apply(m_book, claim, err);
}

bool SwarmCheckpointTrust::claimed(const std::string& claim) const
{
    return m_book.contains(claim);
}

std::string SwarmCheckpointTrust::stored_claim(const std::string& claim) const
{
    return SwarmCheckpointTrustKeep{}.first(m_book, claim);
}

std::size_t SwarmCheckpointTrust::claim_count() const
{
    return m_book.size();
}

bool SwarmCheckpointTrust::trusted() const
{
    if (m_book.trusted()) return true;
    return m_stay.trusted();
}

int64_t SwarmCheckpointTrust::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmCheckpointTrustBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmCheckpointTrust::gpu() const
{
    if (m_book.gpu()) return true;
    return m_quiet.gpu();
}

bool SwarmCheckpointTrust::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
