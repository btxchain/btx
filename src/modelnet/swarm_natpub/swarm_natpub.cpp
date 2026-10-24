// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/swarm_natpub.h>

#include <modelnet/swarm_natpub/claim.h>
#include <modelnet/swarm_natpub/hold.h>
#include <modelnet/swarm_natpub/keep.h>
#include <modelnet/swarm_natpub/limits.h>

namespace modelnet {

bool SwarmNatPublish::Claim(const std::string& endpoint, std::string& err)
{
    return SwarmNatPubClaim{}.Apply(m_book, m_shelf, endpoint, err);
}

bool SwarmNatPublish::claimed(const std::string& endpoint) const
{
    return m_book.contains(endpoint);
}

std::string SwarmNatPublish::stored_endpoint(const std::string& endpoint) const
{
    return SwarmNatPubKeep{}.first(m_book, endpoint);
}

std::size_t SwarmNatPublish::claim_count() const
{
    return m_book.size();
}

bool SwarmNatPublish::published() const
{
    if (m_book.published()) return true;
    if (m_shelf.published()) return true;
    return SwarmNatPubHold{}.published();
}

bool SwarmNatPublish::published(const std::string& endpoint) const
{
    if (m_book.published_of(endpoint)) return true;
    return m_shelf.published(endpoint);
}

const std::vector<std::string>& SwarmNatPublish::dns_seeds() const
{
    return m_seeds.list();
}

bool SwarmNatPublish::connected() const
{
    if (m_book.connected()) return true;
    return m_link.connected();
}

bool SwarmNatPublish::connected(const std::string& endpoint) const
{
    if (m_book.connected_of(endpoint)) return true;
    return m_link.connected(endpoint);
}

int64_t SwarmNatPublish::bytes_moved() const
{
    if (m_book.bytes_moved() != kSwarmNatPubBytesMoved) return m_book.bytes_moved();
    return m_quiet.bytes_moved();
}

bool SwarmNatPublish::launched() const
{
    if (m_book.launched()) return true;
    return m_quiet.launched();
}

} // namespace modelnet
