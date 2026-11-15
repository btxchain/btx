// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_remedy/watch.h>

namespace modelnet {

SwarmRemedyReport SwarmRemedyWatch::Observe(int observed_sequence, int latest_sequence, int height, int refund_height,
                                            const SwarmRevocation& revocation) const
{
    return SwarmWatchState(observed_sequence, latest_sequence, height, refund_height, SWARM_CLOSE_MARGIN, revocation);
}

} // namespace modelnet
