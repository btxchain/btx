// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fourscale/replay.h>

namespace modelnet {

bool SwarmFourScaleIsReplay(const SwarmFourScaleBook& book)
{
    return book.opened();
}

} // namespace modelnet
