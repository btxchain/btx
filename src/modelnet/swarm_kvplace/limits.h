// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_KVPLACE_LIMITS_H
#define BITCOIN_MODELNET_SWARM_KVPLACE_LIMITS_H

#include <cstdint>

namespace modelnet {

/**
 * missing_ppm contributes missing_ppm / 1000, integer division toward zero.
 * The input is rejected when negative, so the dividend is never negative.
 */
inline constexpr std::int64_t kSwarmKvPlaceMissingPpmDivisor = 1000;

static_assert(kSwarmKvPlaceMissingPpmDivisor == 1000, "missing_ppm is divided by 1000");

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_KVPLACE_LIMITS_H
