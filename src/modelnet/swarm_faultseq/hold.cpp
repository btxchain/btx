// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_faultseq/hold.h>

namespace modelnet {

SwarmFaultSeqHold SwarmFaultSeqHold::Idle()
{
    return SwarmFaultSeqHold{};
}

bool SwarmFaultSeqHold::allows_work() const
{
    return !mined && !spent && !broadcast && !live_gpu;
}

} // namespace modelnet
