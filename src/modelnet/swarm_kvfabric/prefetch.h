// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_PREFETCH_H
#define BTX_MODELNET_SWARM_KVFABRIC_PREFETCH_H

#include <modelnet/swarm_kvfabric/result.h>

#include <set>
#include <string>

namespace modelnet {

/**
 * Prefetch records a page id only while the engine status is INSTALLED.
 * Any other status is ENGINE_ABSENT and records nothing. There is no CUDA buffer.
 */
class KvFabricPrefetch {
public:
    SwarmKvFabricResult Request(const std::string& engine_status, const std::string& page);
    bool prefetched(const std::string& page) const;
    bool cuda_buffer() const;

private:
    std::set<std::string> m_pages;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_PREFETCH_H
