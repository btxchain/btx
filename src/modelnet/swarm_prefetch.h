// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_PREFETCH_H
#define BTX_MODELNET_SWARM_PREFETCH_H

#include <cstdint>
#include <string>

namespace modelnet {

// A KV prefetch request is held and moves no bytes.
struct SwarmPrefetchRequest {
    std::string page_id;
    bool want_prefetch;
};

struct SwarmPrefetchResult {
    std::string code;
    bool moved;
    int64_t bytes_moved;
};

SwarmPrefetchResult SwarmNotePrefetch(const SwarmPrefetchRequest& page, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_PREFETCH_H
