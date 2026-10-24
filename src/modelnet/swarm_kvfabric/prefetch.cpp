// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/prefetch.h>

#include <modelnet/swarm_kvfabric/codes.h>

namespace modelnet {

SwarmKvFabricResult KvFabricPrefetch::Request(const std::string& engine_status, const std::string& page)
{
    if (engine_status != kKvFabricInstalled) {
        return KvFabricResult(kKvFabricEngineAbsent);
    }
    if (page.empty()) {
        return KvFabricResult(kKvFabricPage);
    }
    m_pages.insert(page);
    return KvFabricResult(kKvFabricPrefetch);
}

bool KvFabricPrefetch::prefetched(const std::string& page) const
{
    return m_pages.count(page) != 0;
}

bool KvFabricPrefetch::cuda_buffer() const
{
    return false;
}

} // namespace modelnet
