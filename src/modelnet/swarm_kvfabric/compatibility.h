// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_COMPATIBILITY_H
#define BTX_MODELNET_SWARM_KVFABRIC_COMPATIBILITY_H

#include <modelnet/swarm_kvfabric/result.h>

#include <set>
#include <string>

namespace modelnet {

/**
 * Share records a page id when two distinct families are compatible.
 * The same family, or compatible false, is NOT_COMPAT and does not mark the page.
 */
class KvFabricCompatibility {
public:
    SwarmKvFabricResult Share(const std::string& page,
                              const std::string& family_a,
                              const std::string& family_b,
                              bool compatible);
    bool shared(const std::string& page) const;

private:
    std::set<std::string> m_pages;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_COMPATIBILITY_H
