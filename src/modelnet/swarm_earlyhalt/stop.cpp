// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_earlyhalt/stop.h>

namespace modelnet {

void SwarmEarlyHaltStop::Apply(SwarmEarlyHaltRemain& remain, SwarmEarlyHaltMark& mark) const
{
    mark.raise();
    remain.freeze();
}

} // namespace modelnet
