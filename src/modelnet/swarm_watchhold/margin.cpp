// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <compat/wide128.h>
#include <modelnet/swarm_watchhold/margin.h>

#include <modelnet/swarm_watchhold/limits.h>

namespace modelnet {

bool SwarmWatchHoldMarginShort(int64_t height, int64_t refund_height)
{
    const btx::I128 need = static_cast<btx::I128>(height) + static_cast<btx::I128>(kSwarmWatchHoldCloseMargin);
    return static_cast<btx::I128>(refund_height) < need;
}

} // namespace modelnet
