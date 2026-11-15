// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_NAMES_H
#define BITCOIN_MODELNET_SWARM_READFENCE_NAMES_H

#include <string>

namespace modelnet {

/**
 * True when name is one of vllm, sglang, lmcache, nixl, mooncake, rdma.
 * The match is exact. A different case or an unknown name is not known.
 */
bool SwarmReadKnownEngine(const std::string& name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_NAMES_H
