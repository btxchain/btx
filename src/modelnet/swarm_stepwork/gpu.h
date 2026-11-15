// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_STEPWORK_GPU_H
#define BITCOIN_MODELNET_SWARM_STEPWORK_GPU_H

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Refuse a GPU record.
 * Always sets ENGINE_ABSENT and returns false.
 * This function takes no trainer and no experience store, so it cannot
 * call Run or Store and cannot mark a GPU run.
 */
bool SwarmStepWorkRefuseGpu(const std::string& id, int64_t steps, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_STEPWORK_GPU_H
