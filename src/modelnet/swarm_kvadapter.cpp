// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvadapter.h>

namespace modelnet {
namespace {

bool KnownKvEngine(const std::string& engine)
{
    return engine == "vllm" || engine == "sglang" || engine == "lmcache" || engine == "mooncake" ||
           engine == "nixl" || engine == "rdma";
}

} // namespace

SwarmKvAdapterResult SwarmTransferKv(const SwarmKvAdapterRequest& request, std::string& err)
{
    SwarmKvAdapterResult result;
    result.bytes_moved = false;
    if (request.engine.empty() || !KnownKvEngine(request.engine)) {
        result.code = "ENGINE";
        err = "ENGINE";
        return result;
    }
    if (!request.library_present) {
        result.code = "ENGINE_ABSENT";
        err = "ENGINE_ABSENT";
        return result;
    }
    result.code = "LOCAL";
    err.clear();
    return result;
}

} // namespace modelnet
