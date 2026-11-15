// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/placement.h>

#include <modelnet/swarm_kvfabric/bytes.h>
#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricPlacement::Place(const std::string& page, const std::string& family)
{
    if (page.empty() || family.empty()) {
        return KvFabricResult(kKvFabricPage);
    }
    // The family string is an admission check only. The book stores the page id.
    m_pages.insert(page);
    return KvFabricResult(kKvFabricPlaced);
}

bool KvFabricPlacement::placed(const std::string& page) const
{
    return m_pages.count(page) != 0;
}

bool KvFabricPlacement::holds_family() const
{
    return false;
}

bool KvFabricPlacement::bytes_moved() const
{
    return KvFabricBytesMoved();
}

} // namespace modelnet
