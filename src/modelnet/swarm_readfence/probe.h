// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_PROBE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_PROBE_H

#include <modelnet/swarm_readfence/engine.h>

#include <string>

namespace modelnet {

/**
 * Probes one engine name.
 * present false, or a name outside vllm, sglang, lmcache, nixl,
 * mooncake, and rdma, is ENGINE_ABSENT and leaves the engine status
 * unchanged. present true on a known name sets the status to INSTALLED
 * and records that name. Probe does not qualify, advertise, or start
 * a process, and it moves no bytes.
 */
class SwarmReadProbe {
public:
    bool Apply(SwarmReadEngine& engine, const std::string& name, bool present, std::string& err) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_PROBE_H
