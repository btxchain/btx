// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNELSET_LIMITS_H
#define BITCOIN_MODELNET_SWARM_CHANNELSET_LIMITS_H

#include <cstdint>

namespace modelnet {

/**
 * Fee reserve held on the in-memory channel.
 * Zero keeps a cumulative equal to capacity inside SwarmBuildPayout.
 */
inline constexpr int64_t kChannelSetFeeReserve = 0;

/** In-memory templates are not transmitted. This stays 0. */
inline constexpr int64_t kChannelSetBytesMoved = 0;

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNELSET_LIMITS_H
