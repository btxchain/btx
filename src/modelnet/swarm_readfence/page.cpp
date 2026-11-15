// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_readfence/page.h>

namespace modelnet {

bool SwarmReadPage::bind(const std::string& id, const std::string& family)
{
    if (id.empty() || family.empty()) return false;
    m_id = id;
    m_family = family;
    return true;
}

} // namespace modelnet
