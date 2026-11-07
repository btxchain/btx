// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/compatibility.h>

#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricCompatibility::Share(const std::string& page,
                                                 const std::string& family_a,
                                                 const std::string& family_b,
                                                 bool compatible)
{
    if (page.empty() || family_a.empty() || family_b.empty()) {
        return KvFabricResult(kKvFabricPage);
    }
    if (family_a == family_b || !compatible) {
        return KvFabricResult(kKvFabricNotCompat);
    }
    m_pages.insert(page);
    return KvFabricResult(kKvFabricShared);
}

bool KvFabricCompatibility::shared(const std::string& page) const
{
    return m_pages.count(page) != 0;
}

} // namespace modelnet
