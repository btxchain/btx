// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_TOKGATE_CATALOG_H
#define BITCOIN_MODELNET_SWARM_TOKGATE_CATALOG_H

#include <string>

namespace modelnet {

/** Exact engine names this plane will store. No other spelling is stored. */
inline constexpr char kSwarmTokenGateVllm[] = "vllm";
inline constexpr char kSwarmTokenGateSglang[] = "sglang";
inline constexpr char kSwarmTokenGateLmcache[] = "lmcache";

/**
 * True for vllm, sglang, and lmcache only.
 * The compare is bytewise. A different case or an extra byte is not allowed.
 * An allowed name is a stored request. It is not a running process.
 */
bool SwarmTokenGateEngineNameAllowed(const std::string& engine_name);

/**
 * True only when this plane has a running engine for the name.
 * Always false, including for vllm, sglang, and lmcache.
 * A catalog name does not decode and does not move bytes.
 */
bool SwarmTokenGateEngineNameRuns(const std::string& engine_name);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_TOKGATE_CATALOG_H
