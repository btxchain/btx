// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_decode/names.h>

#include <string>

namespace modelnet {

bool SwarmDecodeEngineIsMemory(const std::string& engine)
{
    return engine == kSwarmDecodeMemory;
}

bool SwarmDecodeEngineIsProduction(const std::string& engine)
{
    if (engine == kSwarmDecodeVllm) return true;
    if (engine == kSwarmDecodeSglang) return true;
    if (engine == kSwarmDecodeLmcache) return true;
    return false;
}

bool SwarmDecodeEngineIsKnown(const std::string& engine)
{
    if (SwarmDecodeEngineIsMemory(engine)) return true;
    if (SwarmDecodeEngineIsProduction(engine)) return true;
    return false;
}

} // namespace modelnet
