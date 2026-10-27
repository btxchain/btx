// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_KVFABRIC_ENGINE_NAMES_H
#define BTX_MODELNET_SWARM_KVFABRIC_ENGINE_NAMES_H

#include <string>

namespace modelnet {

/**
 * Closed name list for the KV fabric probe: vllm, sglang, lmcache, nixl,
 * mooncake, rdma. A name check does not start a process.
 */
bool KvFabricKnownEngine(const std::string& name);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_KVFABRIC_ENGINE_NAMES_H
