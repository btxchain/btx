// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DECODE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_DECODE_LIMITS_H

#include <cstdint>

namespace modelnet {

/**
 * A memory Pull stops once text() holds this many bytes.
 * The stream also stops when the stored prompt is exhausted, if that is sooner.
 */
inline constexpr int64_t kSwarmDecodeMemoryByteCap = 8;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DECODE_LIMITS_H
