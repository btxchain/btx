// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVADAPTER_H
#define BTX_MODELNET_SWARM_KVADAPTER_H

#include <string>

namespace modelnet {

/**
 * A KV transfer request. Known engines are vllm, sglang, lmcache,
 * mooncake, nixl, and rdma. library_present is a flag, not a transfer.
 */
struct SwarmKvAdapterRequest {
    std::string engine;
    bool library_present{false};
};

/**
 * A transfer label only. bytes_moved stays false: this function does not
 * move a tensor.
 */
struct SwarmKvAdapterResult {
    bool bytes_moved{false};
    std::string code;
};

/**
 * Order: an empty or unknown engine is ENGINE. A known engine with
 * library_present false is ENGINE_ABSENT, including nixl, mooncake, and
 * rdma. A known engine with library_present true is LOCAL and err is
 * cleared. bytes_moved stays false. A present library flag is not a
 * completed transfer. This function does not move a tensor.
 */
SwarmKvAdapterResult SwarmTransferKv(const SwarmKvAdapterRequest& request, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVADAPTER_H
