// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvfabric/engine_names.h>

namespace modelnet {

bool KvFabricKnownEngine(const std::string& name)
{
    static constexpr const char* kNames[] = {
        "vllm",
        "sglang",
        "lmcache",
        "nixl",
        "mooncake",
        "rdma",
    };
    for (const char* known : kNames) {
        if (name == known) {
            return true;
        }
    }
    return false;
}

} // namespace modelnet
