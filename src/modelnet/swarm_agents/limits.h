// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_AGENTS_LIMITS_H
#define BTX_MODELNET_SWARM_AGENTS_LIMITS_H

#include <cstdint>

namespace modelnet {

/** Inclusive ceiling for a request and for a running per-agent total. */
inline constexpr int64_t kAgentThreadCap = 64;

/** Inclusive ceiling, in MiB, for a request and for a running per-agent total. */
inline constexpr int64_t kAgentMemoryCapMib = 16384;

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_AGENTS_LIMITS_H
