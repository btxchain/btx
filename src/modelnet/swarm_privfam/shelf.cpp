// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_privfam/shelf.h>

namespace modelnet {

bool SwarmPrivFamShelf::published() const
{
    return m_published;
}

bool SwarmPrivFamShelf::published(const std::string& family) const
{
    (void)family;
    return m_published;
}

bool SwarmPrivFamShelf::mark(const std::string& family)
{
    // A private family is not published. The flag stays at its initial value.
    (void)family;
    return m_published;
}

} // namespace modelnet
