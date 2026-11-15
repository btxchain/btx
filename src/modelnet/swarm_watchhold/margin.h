// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_WATCHHOLD_MARGIN_H
#define BITCOIN_MODELNET_SWARM_WATCHHOLD_MARGIN_H

#include <cstdint>

namespace modelnet {

/**
 * True when refund_height is below height + 160.
 * Equality meets the margin and returns false.
 * The sum is formed in a wide integer so a height near the top of int64_t
 * still counts as short when the required refund height does not fit.
 */
bool SwarmWatchHoldMarginShort(int64_t height, int64_t refund_height);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_WATCHHOLD_MARGIN_H
