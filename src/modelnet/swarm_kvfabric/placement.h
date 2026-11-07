// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_PLACEMENT_H
#define BTX_MODELNET_SWARM_KVFABRIC_PLACEMENT_H

#include <modelnet/swarm_kvfabric/result.h>

#include <set>
#include <string>

namespace modelnet {

/** Placement records a page id. An empty page or family is PAGE and stores nothing. */
class KvFabricPlacement {
public:
    SwarmKvFabricResult Place(const std::string& page, const std::string& family);
    bool placed(const std::string& page) const;
    bool holds_family() const;
    bool bytes_moved() const;

private:
    std::set<std::string> m_pages;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_PLACEMENT_H
