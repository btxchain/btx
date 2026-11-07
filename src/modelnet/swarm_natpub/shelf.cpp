// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_natpub/shelf.h>

namespace modelnet {

bool SwarmNatPubShelf::published() const
{
    return m_published;
}

bool SwarmNatPubShelf::published(const std::string& endpoint) const
{
    // A stored endpoint and an unknown endpoint are the same: unpublished.
    (void)endpoint;
    return m_published;
}

bool SwarmNatPubShelf::mark(const std::string& endpoint)
{
    // The endpoint is not published. The flag stays false.
    (void)endpoint;
    return false;
}

} // namespace modelnet
