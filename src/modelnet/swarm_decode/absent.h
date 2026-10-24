// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_ABSENT_H
#define BITCOIN_MODELNET_SWARM_DECODE_ABSENT_H

#include <string>

namespace modelnet {

/**
 * Refuse a Pull on vllm, sglang, or lmcache.
 * Those engines are not linked.
 * Sets ENGINE_ABSENT and returns false.
 * This function does not take the output buffer, so it cannot append a byte
 * and it cannot change tokens().
 */
bool SwarmDecodeProductionPull(std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_ABSENT_H
